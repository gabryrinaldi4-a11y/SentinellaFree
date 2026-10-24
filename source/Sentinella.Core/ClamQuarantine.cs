using System.Security.Cryptography;

namespace Sentinella.Core;

/// <summary>
/// Snapshot-and-rescan workflow for manual ClamAV quarantine. The original is captured
/// from an exclusive stable handle, the exact snapshot is scanned while read-locked,
/// and QuarantineStore verifies its hash again before removing the original.
/// </summary>
public static class ClamQuarantine
{
    public static async Task<QuarantineEntry> IsolateAsync(ClamEngine engine, QuarantineStore store,
        string source, string stagingDirectory, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(engine);
        ArgumentNullException.ThrowIfNull(store);
        cancellationToken.ThrowIfCancellationRequested();
        string original = NativeFiles.NormalizeLocal(source);
        string staging = NativeFiles.NormalizeLocal(stagingDirectory);
        NativeFiles.RejectReparseAncestors(original);
        NativeFiles.RejectReparseAncestors(staging);
        Directory.CreateDirectory(staging);
        NativeFiles.RejectReparseAncestors(staging);
        string snapshot = Path.Combine(staging, Guid.NewGuid().ToString("N") + ".bin");
        string? capturedHash = null;
        bool created = false;
        try
        {
            // An exclusive source handle prevents writes and replacement during capture.
            using (var input = NativeFiles.OpenStable(original, false, true))
            {
                if (input.Length > QuarantineStore.MaxContentBytes)
                    throw new IOException("La quarantena ClamAV è limitata a 32 MiB per file.");
                using var output = new FileStream(snapshot, FileMode.CreateNew, FileAccess.Write,
                    FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough);
                created = true;
                NativeFiles.AssertHandlePath(output.SafeFileHandle, snapshot);
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] buffer = new byte[65536];
                try
                {
                    int count;
                    while ((count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                    {
                        sha.AppendData(buffer, 0, count);
                        await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                    }
                    await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                    output.Flush(true);
                    capturedHash = Convert.ToHexString(sha.GetHashAndReset());
                }
                finally { CryptographicOperations.ZeroMemory(buffer); }
            }
            ClamScanReport report;
            NativeFiles.RejectReparseAncestors(snapshot);
            // Re-open read-only, reject any path replacement, and deny writes/deletion while clamscan reads.
            using (var snapshotLock = new FileStream(snapshot, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                NativeFiles.AssertHandlePath(snapshotLock.SafeFileHandle, snapshot);
                string currentHash = Convert.ToHexString(await SHA256.HashDataAsync(snapshotLock, cancellationToken).ConfigureAwait(false));
                if (!string.Equals(currentHash, capturedHash, StringComparison.Ordinal))
                    throw new IOException("La copia temporanea è cambiata: originale conservato.");
                report = await engine.ScanAsync(snapshot, cancellationToken).ConfigureAwait(false);
            }
            if (report.ExitCode != 1 || !report.IsComplete || !report.Detections.Any(d => !d.IsHeuristicWarning))
                throw new InvalidOperationException("La nuova scansione ClamAV non conferma una minaccia in un'analisi completa: originale conservato.");
            cancellationToken.ThrowIfCancellationRequested();
            string description = "ClamAV: " + string.Join(", ", report.Detections.Where(d => !d.IsHeuristicWarning)
                .Select(d => d.Signature).Distinct(StringComparer.Ordinal).Take(5));
            // LocalHashMatch here binds the source to the exact snapshot bytes actually rescanned.
            // The store reopens the original exclusively and rechecks this hash before deletion.
            return await store.QuarantineAsync(new Finding(original, capturedHash!, "LocalHashMatch", description)).ConfigureAwait(false);
        }
        finally
        {
            if (created && File.Exists(snapshot))
            {
                NativeFiles.RejectReparseAncestors(snapshot);
                // Delete only this operation's exact GUID file, through a verified exclusive handle.
                using var cleanup = NativeFiles.OpenStable(snapshot, true, true);
                if (capturedHash is not null && Convert.ToHexString(SHA256.HashData(cleanup)) != capturedHash)
                    throw new IOException("Copia temporanea sostituita: eliminazione rifiutata. Verifica la cartella di staging.");
                NativeFiles.DeleteOnClose(cleanup);
            }
        }
    }
}
