using System.Security.Cryptography;
using System.Text.Json;

namespace Sentinella.Core;

/// <summary>Exact SHA-256 matches only. No match is not a malware-free verdict.</summary>
public sealed class LocalScanner
{
    public const long MaxFileBytes = 256L * 1024 * 1024;
    private const int MaxFiles = 25000, MaxDirectories = 10000, MaxDepth = 128;
    private const long MaxTotalBytes = 8L * 1024 * 1024 * 1024;
    private readonly Dictionary<string, string> rules = new(StringComparer.OrdinalIgnoreCase);
    public int RuleCount => rules.Count;

    public LocalScanner(string? rulesPath = null)
    {
        if (rulesPath is null) return;
        using var stream = new FileStream(rulesPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > 8 * 1024 * 1024) throw new InvalidDataException("Database firme oltre 8 MiB.");
        using var document = JsonDocument.Parse(stream, new JsonDocumentOptions { MaxDepth = 8 });
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Le regole devono essere un array JSON.");
        if (document.RootElement.GetArrayLength() > 100000)
            throw new InvalidDataException("Troppe regole locali.");
        foreach (var element in document.RootElement.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object ||
                !element.TryGetProperty("sha256", out var hashValue) || hashValue.ValueKind != JsonValueKind.String ||
                !element.TryGetProperty("name", out var nameValue) || nameValue.ValueKind != JsonValueKind.String)
                throw new InvalidDataException("Ogni regola richiede sha256 e name testuali.");
            string hash = hashValue.GetString()!, name = nameValue.GetString()!;
            if (hash.Length != 64 || !hash.All(Uri.IsHexDigit))
                throw new InvalidDataException("SHA-256 non valido.");
            if (string.IsNullOrWhiteSpace(name) || name.Length > 160 || name.Any(char.IsControl))
                throw new InvalidDataException("Nome regola non valido.");
            if (!rules.TryAdd(hash.ToUpperInvariant(), name))
                throw new InvalidDataException("SHA-256 duplicato.");
        }
    }

    public Task<ScanReport> ScanAsync(string target, CancellationToken cancellationToken = default,
        IProgress<string>? progress = null) => Task.Run(() => Scan(target, cancellationToken, progress), cancellationToken);

    private ScanReport Scan(string target, CancellationToken ct, IProgress<string>? progress)
    {
        ct.ThrowIfCancellationRequested();
        string full = NativeFiles.NormalizeLocal(target);
        var started = DateTimeOffset.UtcNow;
        var findings = new List<Finding>();
        var errors = new List<string>();
        int scanned = 0, skipped = 0, directories = 0, seen = 0;
        long totalBytes = 0;
        void Error(string message) { if (errors.Count < 1000) errors.Add(message); }
        void FileScan(string path)
        {
            ct.ThrowIfCancellationRequested();
            if (++seen > MaxFiles) { skipped++; return; }
            progress?.Report(path);
            try
            {
                using var input = NativeFiles.OpenStable(path, false, false);
                if (input.Length > MaxFileBytes || input.Length > MaxTotalBytes - totalBytes)
                { skipped++; Error("Limite dimensione/budget: " + path); return; }
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] buffer = new byte[65536];
                int count;
                while ((count = input.Read(buffer, 0, buffer.Length)) > 0)
                { ct.ThrowIfCancellationRequested(); sha.AppendData(buffer, 0, count); }
                totalBytes += input.Length;
                string hash = Convert.ToHexString(sha.GetHashAndReset());
                bool match = rules.TryGetValue(hash, out string? name);
                findings.Add(new Finding(path, hash, match ? "LocalHashMatch" : "NoLocalMatch",
                    match ? name! : RuleCount == 0
                        ? "Nessun database locale caricato; hash calcolato. Il file non è dichiarato sicuro."
                        : "Nessuna corrispondenza nelle sole firme locali. Il file non è dichiarato sicuro."));
                scanned++;
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            { skipped++; Error(path + ": " + ex.Message); }
        }
        try
        {
            NativeFiles.RejectReparseAncestors(full);
            if (File.Exists(full)) FileScan(full);
            else if (Directory.Exists(full))
            {
                var pending = new Stack<(string Path, int Depth)>();
                pending.Push((full, 0));
                while (pending.Count > 0)
                {
                    ct.ThrowIfCancellationRequested();
                    if (seen >= MaxFiles || directories >= MaxDirectories || totalBytes >= MaxTotalBytes)
                    { Error("Limite globale raggiunto: scansione incompleta."); skipped += pending.Count; break; }
                    var next = pending.Pop();
                    if (next.Depth > MaxDepth)
                    { skipped++; Error("Profondità massima: " + next.Path); continue; }
                    try
                    {
                        NativeFiles.RejectReparseAncestors(next.Path);
                        directories++;
                        foreach (string item in Directory.EnumerateFileSystemEntries(next.Path))
                        {
                            ct.ThrowIfCancellationRequested();
                            if (seen >= MaxFiles)
                            { skipped++; Error("Limite file raggiunto: scansione incompleta."); break; }
                            try
                            {
                                var attrs = File.GetAttributes(item);
                                if ((attrs & FileAttributes.ReparsePoint) != 0)
                                { skipped++; Error("Collegamento escluso: " + item); }
                                else if ((attrs & FileAttributes.Directory) != 0)
                                {
                                    if (pending.Count + directories >= MaxDirectories)
                                    { skipped++; Error("Limite directory: " + item); }
                                    else pending.Push((item, next.Depth + 1));
                                }
                                else FileScan(item);
                            }
                            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                            { skipped++; Error(item + ": " + ex.Message); }
                        }
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    { skipped++; Error(next.Path + ": " + ex.Message); }
                }
            }
            else { skipped++; Error("Percorso inesistente: " + full); }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        { skipped++; Error(full + ": " + ex.Message); }
        return new ScanReport(started, DateTimeOffset.UtcNow, scanned, skipped, findings, errors);
    }
}
