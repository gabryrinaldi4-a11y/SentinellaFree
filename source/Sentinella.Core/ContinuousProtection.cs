using System.Security.Cryptography;
namespace Sentinella.Core;
public interface IContinuousEngine { Task<ClamScanReport> ScanAsync(string path, CancellationToken token); Task UpdateAsync(CancellationToken token); }
public sealed class ClamContinuousEngine(ClamEngine engine) : IContinuousEngine
{
    public Task<ClamScanReport> ScanAsync(string path, CancellationToken token) => engine.ScanAsync(path, token);
    public async Task UpdateAsync(CancellationToken token) { var result = await engine.UpdateAsync(token); if (result.ExitCode != 0) throw new IOException("FreshClam: aggiornamento non confermato, codice " + result.ExitCode); }
}
public sealed class ContinuousProtection : IDisposable
{
    readonly ContinuousSettings config; readonly IContinuousEngine engine; readonly string stateRoot, runtimeRoot;
    readonly DebouncedChanges queue = new(); readonly FileBurstDetector bursts = new(); readonly List<FileSystemWatcher> watchers = [];
    readonly List<ProtectionAlert> alerts = []; readonly object sync = new();
    readonly DateTimeOffset started = DateTimeOffset.UtcNow; long scanned, detections, incomplete;
    DateTimeOffset? updated; string state = "Starting"; string? error; bool overflowReported;
    public ContinuousProtection(ContinuousSettings config, IContinuousEngine engine, string stateRoot, string runtimeRoot)
    { ContinuousConfiguration.Validate(config); this.config = config; this.engine = engine; this.stateRoot = Path.GetFullPath(stateRoot); this.runtimeRoot = Path.GetFullPath(runtimeRoot); }
    static bool Inside(string path, string root) => path.Equals(root, StringComparison.OrdinalIgnoreCase) || path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
    bool Eligible(string path)
    {
        try
        {
            path = NativeFiles.NormalizeLocal(path); NativeFiles.RejectReparseAncestors(path);
            return config.Folders.Any(root => Inside(path, Path.GetFullPath(root))) && !Inside(path, stateRoot) && !Inside(path, runtimeRoot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return false; }
    }
    public void Alert(ProtectionAlert value)
    {
        lock (sync)
        {
            if (alerts.Any(a => a.Kind == value.Kind && a.Subject == value.Subject && value.Time - a.Time < TimeSpan.FromMinutes(2))) return;
            alerts.Insert(0, value); if (alerts.Count > 200) alerts.RemoveRange(200, alerts.Count - 200);
        }
    }
    public bool Queue(string path, DateTimeOffset now)
    {
        if (!Eligible(path)) return false;
        var warning = bursts.Observe(path, now); if (warning is not null) Alert(warning);
        if (queue.Add(path, now)) return true;
        Interlocked.Increment(ref incomplete);
        if (!overflowReported) { overflowReported = true; Alert(new(now, "Warning", "QueueOverflow", "Monitor", "Coda piena: copertura incompleta. Esegui una scansione manuale delle cartelle.")); }
        return false;
    }
    public ContinuousSnapshot Snapshot()
    {
        lock (sync) return new(started, DateTimeOffset.UtcNow, Environment.ProcessId, state, Interlocked.Read(ref scanned), Interlocked.Read(ref detections), Interlocked.Read(ref incomplete), queue.Count, updated, alerts.ToList(), error);
    }
    public async Task<bool> ProcessNextAsync(DateTimeOffset now, CancellationToken token)
    {
        var item = queue.Take(now); if (item is null) return false;
        string path = item.Value.Path; if (!Eligible(path) || !File.Exists(path)) return true;
        try
        {
            string before;
            await using (var input = NativeFiles.OpenStable(path, false, false))
            {
                if (input.Length > 128L * 1024 * 1024) { Interlocked.Increment(ref incomplete); Alert(new(now, "Warning", "SizeLimit", path, "File oltre 128 MiB: escluso dall'analisi automatica, usa la scansione manuale.")); return true; }
                before = Convert.ToHexString(await SHA256.HashDataAsync(input, token));
            }
            var report = await engine.ScanAsync(path, token); token.ThrowIfCancellationRequested();
            string after; await using (var input = NativeFiles.OpenStable(path, false, false)) after = Convert.ToHexString(await SHA256.HashDataAsync(input, token));
            if (before != after) throw new IOException("Il file e cambiato durante la scansione.");
            Interlocked.Increment(ref scanned);
            if (report.Detections.Any(d => !d.IsHeuristicWarning))
            { Interlocked.Increment(ref detections); Alert(new(now, "Detection", "ClamAV", path, string.Join("; ", report.Detections.Where(d => !d.IsHeuristicWarning).Select(d => d.Signature).Take(10)) + ". Nessuna rimozione automatica; verifica in Scansioni/Quarantena.")); }
            if (!report.IsComplete) { Interlocked.Increment(ref incomplete); Alert(new(now, "Warning", "IncompleteScan", path, "ClamAV ha segnalato errori o limiti: il file non e interamente verificato.")); }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            if (item.Value.Attempts < 2) { if (!queue.Add(path, now, item.Value.Attempts + 1)) { Interlocked.Increment(ref incomplete); Alert(new(now, "Warning", "QueueOverflow", path, "Impossibile ritentare: coda piena, esegui una scansione manuale.")); } }
            else { Interlocked.Increment(ref incomplete); Alert(new(now, "Warning", "ScanError", path, ex.Message)); }
        }
        return true;
    }
    public async Task UpdateAsync(CancellationToken token)
    {
        try { lock (sync) state = "UpdatingSignatures"; await engine.UpdateAsync(token); lock (sync) { updated = DateTimeOffset.UtcNow; error = null; } }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { lock (sync) error = "Aggiornamento firme non riuscito: " + ex.Message; Alert(new(DateTimeOffset.UtcNow, "Warning", "SignatureUpdate", "ClamAV", error)); }
        finally { lock (sync) state = "MonitoringAfterWrite"; }
    }
    public async Task RunAsync(CancellationToken token)
    {
        if (!config.Enabled) throw new InvalidOperationException("Monitor non abilitato dall'utente.");
        try
        {
            foreach (string folder in config.Folders.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var watcher = new FileSystemWatcher(folder) { IncludeSubdirectories = true, InternalBufferSize = 32768, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size };
                watcher.Created += (_, e) => Queue(e.FullPath, DateTimeOffset.UtcNow); watcher.Changed += (_, e) => Queue(e.FullPath, DateTimeOffset.UtcNow); watcher.Renamed += (_, e) => Queue(e.FullPath, DateTimeOffset.UtcNow);
                watcher.Error += (_, _) => { Interlocked.Increment(ref incomplete); Alert(new(DateTimeOffset.UtcNow, "Warning", "WatcherOverflow", folder, "Eventi del filesystem persi: copertura incompleta. Esegui una scansione manuale.")); };
                watcher.EnableRaisingEvents = true; watchers.Add(watcher);
            }
            lock (sync) state = "MonitoringAfterWrite";
            while (!token.IsCancellationRequested) { await ProcessNextAsync(DateTimeOffset.UtcNow, token); await Task.Delay(TimeSpan.FromSeconds(1), token); }
        }
        finally { foreach (var watcher in watchers) watcher.EnableRaisingEvents = false; lock (sync) state = "Stopped"; }
    }
    public void Dispose() { foreach (var watcher in watchers) watcher.Dispose(); watchers.Clear(); }
}
