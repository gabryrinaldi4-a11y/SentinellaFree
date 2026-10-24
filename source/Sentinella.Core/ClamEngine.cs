using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace Sentinella.Core;

/// <summary>
/// Runs an explicitly selected, separately distributed ClamAV engine. No PATH lookup,
/// removal switches or cloud sample submissions. Official databases are obtained through
/// FreshClam without disabling its database authentication. This is not a Windows on-access driver.
/// </summary>
public sealed class ClamEngine
{
    private const int MaxCapturedChars = 1024 * 1024, MaxLineChars = 16384, MaxDetections = 25000;
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Gates = new(StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> DatabaseExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".cvd", ".cld", ".ndb", ".ldb", ".hdb", ".hsb", ".mdb", ".msb", ".sdb", ".yar", ".yara", ".cbc" };
    private readonly string engineDirectory, databaseDirectory;
    private readonly SemaphoreSlim gate;
    public string EngineDirectory => engineDirectory;
    public string DatabaseDirectory => databaseDirectory;

    public ClamEngine(string engineDirectory, string databaseDirectory)
    {
        this.engineDirectory = NativeFiles.NormalizeLocal(engineDirectory);
        this.databaseDirectory = NativeFiles.NormalizeLocal(databaseDirectory);
        NativeFiles.RejectReparseAncestors(this.engineDirectory);
        NativeFiles.RejectReparseAncestors(this.databaseDirectory);
        gate = Gates.GetOrAdd(this.databaseDirectory, _ => new SemaphoreSlim(1, 1));
    }

    private string Executable(string name)
    {
        NativeFiles.RejectReparseAncestors(engineDirectory);
        string path = Path.Combine(engineDirectory, name);
        if (!File.Exists(path)) throw new FileNotFoundException("Motore ClamAV non installato: " + name, path);
        NativeFiles.RejectReparseAncestors(path);
        return path;
    }

    public async Task<ClamStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string version = "Non disponibile";
        bool engineAvailable = File.Exists(Path.Combine(engineDirectory, "clamscan.exe"));
        if (engineAvailable)
        {
            try
            {
                var result = await RunAsync(Executable("clamscan.exe"), ["--version"],
                    cancellationToken, TimeSpan.FromSeconds(30), null, null).ConfigureAwait(false);
                engineAvailable = result.ExitCode == 0;
                version = result.ExitCode == 0 ? result.Output.Trim() : "Avvio motore non riuscito";
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            { engineAvailable = false; version = e.Message; }
        }
        NativeFiles.RejectReparseAncestors(databaseDirectory);
        var files = Directory.Exists(databaseDirectory)
            ? Directory.EnumerateFiles(databaseDirectory).Where(p => DatabaseExtensions.Contains(Path.GetExtension(p)))
                .Take(1024).ToList() : [];
        long count = 0;
        DateTimeOffset? updated = null, headerUpdated = null;
        bool main = false, daily = false;
        foreach (string path in files)
        {
            NativeFiles.RejectReparseAncestors(path);
            var info = new FileInfo(path);
            if (info.Length == 0) continue;
            if (updated is null || info.LastWriteTimeUtc > updated.Value.UtcDateTime)
                updated = new DateTimeOffset(info.LastWriteTimeUtc);
            string stem = Path.GetFileNameWithoutExtension(path);
            string extension = Path.GetExtension(path).ToLowerInvariant();
            bool cvd = extension.Equals(".cvd", StringComparison.OrdinalIgnoreCase) || extension.Equals(".cld", StringComparison.OrdinalIgnoreCase);
            if (cvd)
            {
                using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                byte[] header = new byte[512]; int n = input.Read(header);
                string[] parts = Encoding.ASCII.GetString(header, 0, n).TrimEnd('\0', ' ').Split(':');
                if (parts.Length >= 4 && parts[0] == "ClamAV-VDB" && long.TryParse(parts[3], out long signatures))
                {
                    count += Math.Max(0, signatures);
                    if (parts.Length > 8 && long.TryParse(parts[8], out long unixTime))
                    {
                        try { var builtAt = DateTimeOffset.FromUnixTimeSeconds(unixTime); if (headerUpdated is null || builtAt > headerUpdated) headerUpdated = builtAt; }
                        catch (ArgumentOutOfRangeException) { }
                    }
                    if (stem.Equals("main", StringComparison.OrdinalIgnoreCase)) main = true;
                    if (stem.Equals("daily", StringComparison.OrdinalIgnoreCase)) daily = true;
                }
            }
            else if (info.Length <= 16L * 1024 * 1024 && extension is ".ndb" or ".hdb" or ".hsb" or ".mdb" or ".msb" or ".sdb" or ".ldb")
            {
                count += File.ReadLines(path).LongCount(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith('#'));
            }
        }
        bool present = files.Any(p => new FileInfo(p).Length > 0);
        return new ClamStatus(engineAvailable, version, present, main && daily, count, headerUpdated ?? updated,
            files.Select(Path.GetFileName).OfType<string>().ToList(),
            !present ? "Database assente: occorre aggiornare le firme prima di analizzare file."
            : main && daily ? "Database rilevati. L'autenticazione e la validità sono controllate dal motore al caricamento; il conteggio è ricavato dagli header."
            : "Sono presenti soltanto database parziali o personalizzati: non equivalgono alle firme ufficiali complete.");
    }

    public async Task<ClamScanReport> ScanAsync(string target, CancellationToken cancellationToken = default,
        IProgress<string>? progress = null)
    {
        string full = NativeFiles.NormalizeLocal(target);
        if (full.Any(char.IsControl)) throw new IOException("Il percorso contiene caratteri di controllo non supportati.");
        NativeFiles.RejectReparseAncestors(full);
        if (!File.Exists(full) && !Directory.Exists(full)) throw new FileNotFoundException("Il percorso da analizzare non esiste.", full);
        string scanner = Executable("clamscan.exe");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        var started = DateTimeOffset.UtcNow;
        try
        {
            var status = await GetStatusAsync(cancellationToken).ConfigureAwait(false);
            if (!status.DatabaseAvailable) throw new InvalidOperationException("ClamAV non ha database: aggiorna le firme prima della scansione.");
            var detections = new List<ClamDetection>();
            var warnings = new List<string>();
            int scannedFiles = 0;
            bool detectionOverflow = false, outputProblem = false;
            void Observe(string line)
            {
                if (line.EndsWith(" FOUND", StringComparison.Ordinal))
                {
                    string body = line[..^6];
                    int delimiter = body.LastIndexOf(": ", StringComparison.Ordinal);
                    if (delimiter > 0)
                    {
                        string path = body[..delimiter], signature = body[(delimiter + 2)..];
                        bool limitation = signature.StartsWith("Heuristics.Limits.Exceeded", StringComparison.OrdinalIgnoreCase)
                            || signature.StartsWith("Heuristics.Encrypted", StringComparison.OrdinalIgnoreCase);
                        if (detections.Count < MaxDetections) detections.Add(new ClamDetection(path, signature, limitation));
                        else detectionOverflow = true;
                        if (limitation && warnings.Count < 1000) warnings.Add(path + ": " + signature + ". Contenuto non interamente ispezionabile.");
                    }
                    else { outputProblem = true; if(warnings.Count < 1000) warnings.Add("Rilevamento non interpretabile: " + line); }
                }
                if (line.StartsWith("Scanned files:", StringComparison.OrdinalIgnoreCase))
                    int.TryParse(line[14..].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out scannedFiles);
                if (line.Contains("ERROR", StringComparison.OrdinalIgnoreCase) || line.Contains("WARNING", StringComparison.OrdinalIgnoreCase)
                    || line.Contains("skipped", StringComparison.OrdinalIgnoreCase) || line.Contains("Access is denied", StringComparison.OrdinalIgnoreCase)
                    || line.Contains("permission denied", StringComparison.OrdinalIgnoreCase))
                { outputProblem = true; if (warnings.Count < 1000) warnings.Add(line); }
            }
            var result = await RunAsync(scanner,
                ["--database=" + databaseDirectory, "--recursive=yes", "--infected", "--stdout", "--scan-archive=yes",
                 "--follow-dir-symlinks=0", "--follow-file-symlinks=0", "--max-filesize=256M", "--max-scansize=512M",
                 "--max-recursion=20", "--max-dir-recursion=128", "--max-files=10000", "--alert-exceeds-max=yes",
                 "--alert-encrypted=yes", full], cancellationToken, TimeSpan.FromHours(12), progress, Observe).ConfigureAwait(false);
            bool complete = result.ExitCode is 0 or 1 && !outputProblem && !detectionOverflow
                && !result.OutputTruncated && scannedFiles > 0 && !detections.Any(d => d.IsHeuristicWarning);
            if (scannedFiles == 0) warnings.Add("Il motore non ha riportato file analizzati: nessuna conclusione di assenza minacce.");
            if (result.OutputTruncated) warnings.Add("Output oltre il limite di conservazione: rapporto incompleto.");
            if (detectionOverflow) warnings.Add("Limite del numero di rilevamenti raggiunto: rapporto incompleto.");
            if (result.ExitCode is not (0 or 1)) warnings.Add("Il motore ha restituito un errore: nessuna conclusione di assenza minacce.");
            if (!status.OfficialDatabasesPresent) warnings.Add("Database ufficiali main/daily non entrambi presenti; copertura delle firme parziale o personalizzata.");
            string verdict = detections.Any(d => !d.IsHeuristicWarning) ? "ThreatsDetected"
                : !complete || result.ExitCode != 0 ? "Incomplete" : "NoDetectionsWithinScope";
            return new ClamScanReport(started, DateTimeOffset.UtcNow, status.EngineVersion, full, result.ExitCode,
                verdict, complete, scannedFiles, detections, warnings, result.Output, result.StandardError);
        }
        finally { gate.Release(); }
    }

    public async Task<EngineCommandResult> UpdateAsync(CancellationToken cancellationToken = default,
        IProgress<string>? progress = null)
    {
        string updater = Executable("freshclam.exe");
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            NativeFiles.RejectReparseAncestors(databaseDirectory);
            Directory.CreateDirectory(databaseDirectory);
            string config = Path.Combine(databaseDirectory, "freshclam.sentinella.conf");
            NativeFiles.RejectReparseAncestors(config);
            string content = "DatabaseDirectory \"" + databaseDirectory + "\"\n"
                + "DatabaseMirror database.clamav.net\nDNSDatabaseInfo current.cvd.clamav.net\n"
                + "Checks 1\nMaxAttempts 1\nConnectTimeout 20\nReceiveTimeout 60\n"
                + "ScriptedUpdates yes\nTestDatabases yes\nBytecode yes\n";
            await File.WriteAllTextAsync(config, content, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
            return await RunAsync(updater, ["--config-file=" + config, "--datadir=" + databaseDirectory, "--stdout"],
                cancellationToken, TimeSpan.FromMinutes(45), progress, null).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    private async Task<EngineCommandResult> RunAsync(string executable, IReadOnlyList<string> arguments,
        CancellationToken token, TimeSpan timeout, IProgress<string>? progress, Action<string>? observe)
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        // The pinned 1.5.4 binary emits UTF-8 here; older builds may emit OEM. Decode bounded lines strictly, with an explicit incomplete fallback.
        Encoding encoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage);
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
            WorkingDirectory = engineDirectory, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = encoding, StandardErrorEncoding = encoding };
        foreach (string argument in arguments) info.ArgumentList.Add(argument);
        using var process = new Process { StartInfo = info };
        if (!process.Start()) throw new IOException("Impossibile avviare ClamAV.");
        int truncated = 0;
        async Task<string> ReadAsync(Stream stream)
        {
            var captured = new StringBuilder(); var line = new List<byte>();
            byte[] buffer = new byte[4096]; bool longLine = false;
            var strictUtf8 = new UTF8Encoding(false, true);
            void Emit()
            {
                if (longLine) { Interlocked.Exchange(ref truncated, 1); line.Clear(); longLine = false; return; }
                string value;
                try { value = strictUtf8.GetString(line.ToArray()).TrimEnd('\r'); }
                catch (DecoderFallbackException)
                {
                    // Older Windows builds can emit OEM. Retain it, but mark encoding uncertainty incomplete.
                    value = encoding.GetString(line.ToArray()).TrimEnd('\r');
                    Interlocked.Exchange(ref truncated, 1);
                }
                line.Clear();
                int remaining = MaxCapturedChars - captured.Length;
                if (value.Length + 1 > remaining) Interlocked.Exchange(ref truncated, 1);
                if (remaining > 0) captured.Append(value.AsSpan(0, Math.Min(value.Length, remaining)));
                if (captured.Length < MaxCapturedChars) captured.Append('\n');
                observe?.Invoke(value);
                try { progress?.Report(value.Length > 500 ? value[..500] : value); }
                catch { Interlocked.Exchange(ref truncated, 1); }
            }
            int n;
            while ((n = await stream.ReadAsync(buffer.AsMemory(), CancellationToken.None).ConfigureAwait(false)) > 0)
            {
                for (int i = 0; i < n; i++)
                {
                    byte b = buffer[i];
                    if (b == 10) Emit();
                    else if (line.Count < MaxLineChars) line.Add(b);
                    else longLine = true;
                }
            }
            if (line.Count > 0 || longLine) Emit();
            return captured.ToString();
        }
        // Callbacks from stdout and stderr can arrive concurrently; serialize evidence parsing.
        object observationGate = new();
        Action<string>? original = observe;
        if (original is not null) observe = line => { lock(observationGate) original(line); };
        var stdout = ReadAsync(process.StandardOutput.BaseStream); var stderr = ReadAsync(process.StandardError.BaseStream);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(timeout);
        try { await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException)
        {
            try { process.Kill(true); } catch (InvalidOperationException) { }
            await Task.WhenAll(stdout, stderr).ConfigureAwait(false);
            throw new OperationCanceledException(token.IsCancellationRequested ? "Scansione ClamAV annullata." : "Tempo massimo ClamAV superato.", token);
        }
        return new EngineCommandResult(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false), truncated != 0);
    }
}



