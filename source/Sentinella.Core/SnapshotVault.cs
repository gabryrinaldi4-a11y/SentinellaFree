using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace Sentinella.Core;

/// <summary>
/// Manual versioned backups with SHA-256 integrity. Local snapshots are not isolated from the
/// same user/admin, do not prevent ransomware and do not provide a globally consistent volume snapshot.
/// Restore always creates a new directory, never overwrites and never executes content.
/// </summary>
public sealed class SnapshotVault
{
    public const long MaxFileBytes = 128L * 1024 * 1024;
    public const long MaxTotalBytes = 2L * 1024 * 1024 * 1024;
    public const int MaxFiles = 20000, MaxDirectories = 10000;
    private const int MaxManifestBytes = 32 * 1024 * 1024, MaxErrors = 1000;
    private readonly string vault;
    private readonly SemaphoreSlim gate = new(1, 1);
    private record StoredFile(string Path, long Bytes, string Sha256);
    private record Manifest(int Format, SnapshotInfo Info, List<StoredFile> Files, List<string> Directories);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateDirectoryW(string path, IntPtr securityAttributes);

    public SnapshotVault(string vaultDirectory)
    {
        vault = Path.TrimEndingDirectorySeparator(NativeFiles.NormalizeLocal(vaultDirectory));
        NativeFiles.RejectReparseAncestors(vault);
        Directory.CreateDirectory(vault);
        NativeFiles.RejectReparseAncestors(vault);
    }

    public async Task<SnapshotInfo> CreateAsync(string sourceDirectory, CancellationToken cancellationToken = default,
        IProgress<string>? progress = null)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { return await Task.Run(() => Create(sourceDirectory, cancellationToken, progress), cancellationToken).ConfigureAwait(false); }
        finally { gate.Release(); }
    }

    public IReadOnlyList<SnapshotInfo> List()
    {
        gate.Wait();
        try
        {
            NativeFiles.RejectReparseAncestors(vault);
            var result = new List<SnapshotInfo>();
            foreach (string dir in Directory.EnumerateDirectories(vault))
            {
                string id = Path.GetFileName(dir);
                if (!Guid.TryParseExact(id, "N", out _)) continue; // Incomplete staging is never listed as committed.
                if (result.Count >= 10000) throw new IOException("Troppe versioni nel deposito backup.");
                result.Add(Read(id).Info);
            }
            return result.OrderByDescending(x => x.CreatedAt).ToList();
        }
        finally { gate.Release(); }
    }

    public async Task RestoreAsync(string id, string newDestinationDirectory, CancellationToken cancellationToken = default,
        IProgress<string>? progress = null)
    {
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try { await Task.Run(() => Restore(id, newDestinationDirectory, cancellationToken, progress), cancellationToken).ConfigureAwait(false); }
        finally { gate.Release(); }
    }

    private SnapshotInfo Create(string directory, CancellationToken ct, IProgress<string>? progress)
    {
        ct.ThrowIfCancellationRequested();
        string source = Path.TrimEndingDirectorySeparator(NativeFiles.NormalizeLocal(directory));
        NativeFiles.RejectReparseAncestors(source);
        NativeFiles.RejectReparseAncestors(vault);
        if (!Directory.Exists(source)) throw new DirectoryNotFoundException("Cartella sorgente non disponibile.");
        if (Related(source, vault)) throw new IOException("Il deposito backup e la sorgente devono essere cartelle separate, senza contenerle una dentro l'altra.");
        string id = Guid.NewGuid().ToString("N"), stage = Path.Combine(vault, ".staging-" + id), final = ItemDirectory(id);
        CreateNewDirectory(stage);
        string data = Path.Combine(stage, "data"); CreateNewDirectory(data);
        var files = new List<StoredFile>(); var directories = new List<string>(); var errors = new List<string>();
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long bytes = 0; int visitedDirectories = 0, visitedFiles = 0, visitedEntries = 0;
        void Error(string text) { if (errors.Count < MaxErrors) errors.Add(text.Length > 2048 ? text[..2048] : text); }
        var pending = new Stack<(string Path, int Depth)>(); pending.Push((source, 0));
        while (pending.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            if (visitedDirectories >= MaxDirectories || visitedFiles >= MaxFiles || visitedEntries >= MaxFiles + MaxDirectories)
            { Error("Limite di elementi raggiunto: backup incompleto."); break; }
            var next = pending.Pop();
            if (next.Depth > 128) { Error("Profondità massima superata: " + next.Path); continue; }
            try
            {
                NativeFiles.RejectReparseAncestors(next.Path);
                visitedDirectories++;
                if (!string.Equals(next.Path, source, StringComparison.OrdinalIgnoreCase))
                {
                    string relative = Relative(source, next.Path);
                    if (!paths.Add(relative)) { Error("Percorso duplicato: " + relative); continue; }
                    directories.Add(relative);
                    string folder = Child(data, relative); NativeFiles.RejectReparseAncestors(folder); Directory.CreateDirectory(folder);
                }
                foreach (string entry in Directory.EnumerateFileSystemEntries(next.Path))
                {
                    ct.ThrowIfCancellationRequested();
                    if (++visitedEntries > MaxFiles + MaxDirectories) { Error("Limite di elementi raggiunto: backup incompleto."); break; }
                    try
                    {
                        var attrs = File.GetAttributes(entry);
                        if ((attrs & FileAttributes.ReparsePoint) != 0) { Error("Collegamento escluso: " + entry); continue; }
                        if ((attrs & FileAttributes.Directory) != 0)
                        {
                            if (pending.Count + visitedDirectories >= MaxDirectories) Error("Limite directory: " + entry);
                            else pending.Push((entry, next.Depth + 1));
                            continue;
                        }
                        if (++visitedFiles > MaxFiles) { Error("Limite file raggiunto: backup incompleto."); break; }
                        string relative = Relative(source, entry);
                        if (!paths.Add(relative)) { Error("Percorso duplicato: " + relative); continue; }
                        progress?.Report(relative);
                        using var input = NativeFiles.OpenStable(entry, false, false);
                        long length = input.Length;
                        if (length > MaxFileBytes || length > MaxTotalBytes - bytes) { Error("Limite dimensione/budget: " + relative); continue; }
                        string target = Child(data, relative);
                        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                        NativeFiles.RejectReparseAncestors(target);
                        bool created = false;
                        try
                        {
                            string hash;
                            using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
                            {
                                created = true; NativeFiles.AssertHandlePath(output.SafeFileHandle, target);
                                hash = CopyHash(input, output, length, ct); output.Flush(true);
                            }
                            var stored = new StoredFile(relative, length, hash);
                            VerifyFile(data, stored, ct);
                            files.Add(stored); bytes += length;
                        }
                        catch
                        {
                            // Delete only this just-created partial file; never recursively remove a source or destination.
                            if (created) TryDeletePartial(stage, target);
                            throw;
                        }
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex) when (Expected(ex)) { Error(entry + ": " + ex.Message); }
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (Expected(ex)) { Error(next.Path + ": " + ex.Message); }
        }
        ct.ThrowIfCancellationRequested();
        var info = new SnapshotInfo(id, source, DateTimeOffset.UtcNow, files.Count, bytes, errors.Count == 0, errors);
        var manifest = new Manifest(1, info, files, directories);
        string manifestPath = Path.Combine(stage, "manifest.json");
        using (var stream = new FileStream(manifestPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough))
        {
            NativeFiles.AssertHandlePath(stream.SafeFileHandle, manifestPath);
            JsonSerializer.Serialize(stream, manifest); stream.Flush(true);
            if (stream.Length > MaxManifestBytes) throw new IOException("Manifest backup oltre il limite; acquisizione non pubblicata.");
        }
        NativeFiles.RejectReparseAncestors(stage); NativeFiles.RejectReparseAncestors(vault);
        Validate(manifest, id);
        foreach (var item in files) VerifyFile(data, item, ct);
        ct.ThrowIfCancellationRequested();
        Directory.Move(stage, final); // Commit of an owned, new version only; source files are never moved.
        return info;
    }

    private void Restore(string id, string destinationDirectory, CancellationToken ct, IProgress<string>? progress)
    {
        ct.ThrowIfCancellationRequested();
        var manifest = Read(id);
        string sourceData = Path.Combine(ItemDirectory(id), "data");
        string destination = Path.TrimEndingDirectorySeparator(NativeFiles.NormalizeLocal(destinationDirectory));
        NativeFiles.RejectReparseAncestors(destination);
        if (Related(destination, vault)) throw new IOException("Ripristina fuori dal deposito backup e dalle sue cartelle parenti.");
        if (Directory.Exists(destination) || File.Exists(destination)) throw new IOException("Il ripristino richiede una cartella nuova che non esiste ancora.");
        string? parent = Path.GetDirectoryName(destination);
        if (parent is null || !Directory.Exists(parent)) throw new DirectoryNotFoundException("La cartella padre della destinazione deve esistere.");
        // Verify every stored file before creating any restore destination.
        foreach (var item in manifest.Files) { ct.ThrowIfCancellationRequested(); progress?.Report("Verifica " + item.Path); VerifyFile(sourceData, item, ct); }
        ct.ThrowIfCancellationRequested();
        NativeFiles.RejectReparseAncestors(destination);
        CreateNewDirectory(destination); // Unlike CreateDirectory, fails if another process already created it.
        try
        {
            foreach (string relative in manifest.Directories)
            {
                ct.ThrowIfCancellationRequested(); string target = Child(destination, relative);
                NativeFiles.RejectReparseAncestors(target); Directory.CreateDirectory(target);
            }
            foreach (var item in manifest.Files)
            {
                ct.ThrowIfCancellationRequested(); progress?.Report("Ripristino " + item.Path);
                string target = Child(destination, item.Path); NativeFiles.RejectReparseAncestors(target);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                using var input = NativeFiles.OpenStable(Child(sourceData, item.Path), false, false);
                if (input.Length != item.Bytes) throw new InvalidDataException("Dimensione backup cambiata: " + item.Path);
                using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.WriteThrough);
                NativeFiles.AssertHandlePath(output.SafeFileHandle, target);
                if (!string.Equals(CopyHash(input, output, item.Bytes, ct), item.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("Integrità backup cambiata durante il ripristino: " + item.Path);
                output.Flush(true);
            }
        }
        catch (OperationCanceledException ex)
        {
            throw new OperationCanceledException("Ripristino interrotto; la nuova destinazione può contenere una copia parziale. Gli originali e il backup sono conservati.", ex, ct);
        }
        catch (Exception ex) when (Expected(ex))
        {
            throw new IOException("Ripristino interrotto; la nuova destinazione può contenere una copia parziale. Gli originali e il backup sono conservati. " + ex.Message, ex);
        }
    }

    private Manifest Read(string id)
    {
        string directory = ItemDirectory(id); NativeFiles.RejectReparseAncestors(directory);
        using var stream = NativeFiles.OpenStable(Path.Combine(directory, "manifest.json"), false, false);
        if (stream.Length > MaxManifestBytes) throw new InvalidDataException("Manifest backup oltre il limite.");
        var manifest = JsonSerializer.Deserialize<Manifest>(stream, new JsonSerializerOptions { MaxDepth = 12 })
            ?? throw new InvalidDataException("Manifest backup vuoto.");
        Validate(manifest, id); return manifest;
    }

    private static void Validate(Manifest manifest, string id)
    {
        if (manifest.Format != 1 || manifest.Info is null || manifest.Info.Id != id || manifest.Files is null || manifest.Directories is null ||
            manifest.Info.Errors is null || manifest.Info.Errors.Count > MaxErrors || manifest.Info.Source is null || manifest.Info.Source.Length > 32768 ||
            manifest.Files.Count > MaxFiles || manifest.Directories.Count > MaxDirectories || manifest.Info.FileCount != manifest.Files.Count ||
            manifest.Info.TotalBytes < 0 || manifest.Info.TotalBytes > MaxTotalBytes || (manifest.Info.Complete && manifest.Info.Errors.Count != 0))
            throw new InvalidDataException("Manifest backup non valido.");
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase); long bytes = 0;
        foreach (string relative in manifest.Directories)
            if (!paths.Add(ValidateRelative(relative))) throw new InvalidDataException("Percorso backup duplicato.");
        foreach (var item in manifest.Files)
        {
            if (item is null || item.Bytes < 0 || item.Bytes > MaxFileBytes || item.Sha256 is null || item.Sha256.Length != 64 || !item.Sha256.All(Uri.IsHexDigit) ||
                !paths.Add(ValidateRelative(item.Path))) throw new InvalidDataException("Elemento backup non valido.");
            bytes += item.Bytes; if (bytes > MaxTotalBytes) throw new InvalidDataException("Budget backup non valido.");
        }
        if (bytes != manifest.Info.TotalBytes) throw new InvalidDataException("Conteggio byte backup non valido.");
        // A file cannot act as an ancestor directory for another stored path.
        var filePaths = new HashSet<string>(manifest.Files.Select(x => ValidateRelative(x.Path)), StringComparer.OrdinalIgnoreCase);
        foreach (string path in paths)
        {
            string? ancestor = Path.GetDirectoryName(path);
            while (!string.IsNullOrEmpty(ancestor))
            {
                if (filePaths.Contains(ancestor)) throw new InvalidDataException("Conflitto file/directory nel backup.");
                ancestor = Path.GetDirectoryName(ancestor);
            }
        }
        if (manifest.Info.Errors.Any(x => x is null || x.Length > 2048)) throw new InvalidDataException("Dettagli backup non validi.");
    }

    private string ItemDirectory(string id)
    {
        if (!Guid.TryParseExact(id, "N", out _)) throw new InvalidDataException("ID backup non valido.");
        return Path.Combine(vault, id);
    }
    private static string Relative(string root, string path) => ValidateRelative(Path.GetRelativePath(root, path));
    private static string ValidateRelative(string relative)
    {
        if (string.IsNullOrWhiteSpace(relative) || relative.Length > 2048 || Path.IsPathRooted(relative) || relative.Any(char.IsControl) || relative.Contains(':'))
            throw new InvalidDataException("Percorso relativo backup non valido.");
        string normalized = relative.Replace('/', Path.DirectorySeparatorChar);
        foreach (string part in normalized.Split(Path.DirectorySeparatorChar))
        {
            if (part.Length == 0 || part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.') || part.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
                throw new InvalidDataException("Segmento percorso backup non valido.");
            string stem = part.Split('.')[0].ToUpperInvariant();
            if (stem is "CON" or "PRN" or "AUX" or "NUL" ||
                (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] is >= '0' and <= '9'))
                throw new InvalidDataException("Nome dispositivo non ammesso nel backup.");
        }
        return normalized;
    }
    private static string Child(string root, string relative)
    {
        string child = Path.GetFullPath(Path.Combine(root, ValidateRelative(relative)));
        if (!child.StartsWith(Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Percorso fuori dal deposito backup.");
        return child;
    }
    private static bool Related(string first, string second) =>
        string.Equals(first, second, StringComparison.OrdinalIgnoreCase) ||
        first.StartsWith(second.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
        second.StartsWith(first.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    private static bool Expected(Exception ex) => ex is IOException or InvalidDataException or UnauthorizedAccessException or Win32Exception or CryptographicException or JsonException;
    private static void CreateNewDirectory(string directory)
    {
        NativeFiles.RejectReparseAncestors(directory);
        if (!CreateDirectoryW(directory, IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Impossibile creare una nuova cartella esclusiva: " + directory);
        NativeFiles.RejectReparseAncestors(directory);
    }
    private static string CopyHash(Stream input, Stream? output, long expected, CancellationToken ct)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[65536]; long count = 0; int read;
        while ((read = input.Read(buffer, 0, buffer.Length)) != 0)
        {
            ct.ThrowIfCancellationRequested(); count += read;
            if (count > expected || count > MaxFileBytes) throw new IOException("Il contenuto supera la dimensione dichiarata.");
            hash.AppendData(buffer, 0, read); output?.Write(buffer, 0, read);
        }
        if (count != expected) throw new IOException("Il contenuto è più corto della dimensione dichiarata.");
        return Convert.ToHexString(hash.GetHashAndReset());
    }
    private static void VerifyFile(string data, StoredFile item, CancellationToken ct)
    {
        using var input = NativeFiles.OpenStable(Child(data, item.Path), false, false);
        if (input.Length != item.Bytes || !string.Equals(CopyHash(input, null, item.Bytes, ct), item.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Verifica SHA-256 backup non riuscita: " + item.Path);
    }
    private static void TryDeletePartial(string stage, string target)
    {
        try
        {
            string full = Path.GetFullPath(target);
            if (!full.StartsWith(Path.TrimEndingDirectorySeparator(stage) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return;
            NativeFiles.RejectReparseAncestors(stage); NativeFiles.RejectReparseAncestors(full);
            File.Delete(full);
        }
        catch (Exception ex) when (Expected(ex)) { /* Retain the private partial file rather than broaden cleanup. */ }
    }
}


