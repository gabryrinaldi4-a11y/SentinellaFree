using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Sentinella.Core;
namespace Sentinella.Desktop;
internal static class AgentClient
{
    public static string Config(string state) => Path.Combine(state, "continuous", "settings.json");
    public static string SnapshotPath(string state) => Path.Combine(state, "continuous", "status.json");
    public static string PipeName(string state) => "Sentinella-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(AppControlWindows.UserSid + Path.GetFullPath(state).ToUpperInvariant())))[..24];
    public static ContinuousSnapshot? Read(string state)
    {
        string path = SnapshotPath(state); if (!File.Exists(path)) return null;
        if (new FileInfo(path).Length > 1024 * 1024) throw new IOException("Stato agente oltre il limite.");
        return JsonSerializer.Deserialize<ContinuousSnapshot>(File.ReadAllText(path));
    }
    public static async Task Start(string state, string runtime, ContinuousSettings config)
    {
        var current = Read(state);
        if (current is not null && DateTimeOffset.UtcNow - current.Heartbeat < TimeSpan.FromSeconds(12) && current.State is not ("Stopped" or "Faulted"))
            throw new IOException("Un agente risponde gia. Fermalo prima di cambiare configurazione.");
        ContinuousConfiguration.Save(Config(state), config);
        var info = new ProcessStartInfo(AppControlWindows.OwnExecutable) { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden, WorkingDirectory = AppContext.BaseDirectory };
        foreach (string arg in new[] { "--agent", "--runtime-root", runtime, "--state-root", state }) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new IOException("Agente non avviato.");
        for (int i = 0; i < 30; i++)
        {
            await Task.Delay(500); current = Read(state);
            if (current?.ProcessId == process.Id && current.State == "MonitoringAfterWrite") return;
            if (process.HasExited) throw new IOException("Agente terminato: " + (current?.Error ?? "controlla eventuali blocchi di Windows"));
        }
        throw new IOException("Avvio non confermato: controlla lo stato prima di riprovare.");
    }
    public static async Task Stop(string state)
    {
        var config = ContinuousConfiguration.Load(Config(state)); ContinuousConfiguration.Save(Config(state), config with { Enabled = false });
        using var pipe = new NamedPipeClientStream(".", PipeName(state), PipeDirection.InOut, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await pipe.ConnectAsync(timeout.Token); }
        catch (OperationCanceledException) when (Read(state)?.State == "Stopped") { return; }
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        await writer.WriteLineAsync("stop");
        using var reader = new StreamReader(pipe, leaveOpen: true);
        if (await reader.ReadLineAsync(timeout.Token) != "stopping") throw new IOException("Arresto non confermato.");
    }
    public static void SetLogon(bool enabled, string state, string runtime)
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
        const string name = "SentinellaFreeUserAgent";
        if (!enabled) { key.DeleteValue(name, false); return; }
        foreach (string path in new[] { state, runtime, AppControlWindows.OwnExecutable }) { AppControlWindows.ValidatePath(path); if (path.Contains('"')) throw new IOException("Percorso non valido."); }
        key.SetValue(name, "\"" + AppControlWindows.OwnExecutable + "\" --agent --runtime-root \"" + runtime + "\" --state-root \"" + state + "\"");
    }
}
internal static class BackgroundAgent
{
    sealed record ObservedProcess(int Pid, string Created, string Path, string? Command, string? Parent);
    public static async Task Run(string state, string runtime)
    {
        AppControlWindows.ValidatePath(state); AppControlWindows.ValidatePath(runtime);
        var config = ContinuousConfiguration.Load(AgentClient.Config(state)); if (!config.Enabled) return;
        using var singleton = new AgentLifetimeLock(@"Local\" + AgentClient.PipeName(state));
        if (!singleton.Acquired) return;
        var clam = new ClamEngine(Path.Combine(runtime, "clamav"), Path.Combine(runtime, "database"));
        var availability = await clam.GetStatusAsync();
        if (!availability.EngineAvailable || !availability.OfficialDatabasesPresent) throw new IOException("L'agente richiede il motore e i database ufficiali ClamAV disponibili.");
        using var stop = new CancellationTokenSource();
        using var engine = new ContinuousProtection(config, new ClamContinuousEngine(clam), state, runtime);
        var tasks = new List<Task>();
        try
        {
            engine.Alert(new(DateTimeOffset.UtcNow, "Info", "Integrity", "Installazione", InstallationIntegrity.Check(AppContext.BaseDirectory)));
            if (availability.DatabaseUpdatedAt is null || DateTimeOffset.UtcNow - availability.DatabaseUpdatedAt > TimeSpan.FromDays(3)) engine.Alert(new(DateTimeOffset.UtcNow, "Warning", "OldDefinitions", "ClamAV", "Database vecchi o data non disponibile: aggiorna le firme prima di contare sulla copertura."));
            tasks.Add(engine.RunAsync(stop.Token)); tasks.Add(Heartbeat()); tasks.Add(Commands());
            if (config.AutoUpdateSignatures) tasks.Add(Updates());
            if (config.ObserveProcesses) tasks.Add(Processes());
            Task first = await Task.WhenAny(tasks); await first;
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (Exception ex) { engine.Alert(new(DateTimeOffset.UtcNow, "Warning", "AgentFailure", "Agente", ex.Message)); }
        finally
        {
            stop.Cancel();
            AtomicJson.Write(AgentClient.SnapshotPath(state), engine.Snapshot() with { State = "Stopping" });
            try { await Task.WhenAll(tasks); } catch (Exception) { }
            AtomicJson.Write(AgentClient.SnapshotPath(state), engine.Snapshot() with { State = "Stopped" });
        }
        async Task Heartbeat()
        {
            while (!stop.IsCancellationRequested)
            {
                AtomicJson.Write(AgentClient.SnapshotPath(state), engine.Snapshot());
                if (!ContinuousConfiguration.Load(AgentClient.Config(state)).Enabled) stop.Cancel();
                await Task.Delay(2000, stop.Token);
            }
        }
        async Task Commands()
        {
            while (!stop.IsCancellationRequested)
            {
                using var server = new NamedPipeServerStream(AgentClient.PipeName(state), PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(stop.Token);
                using var reader = new StreamReader(server, leaveOpen: true);
                using var writer = new StreamWriter(server, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop.Token); timeout.CancelAfter(TimeSpan.FromSeconds(3));
                try { if (await reader.ReadLineAsync(timeout.Token) == "stop") { await writer.WriteLineAsync("stopping"); stop.Cancel(); } else await writer.WriteLineAsync("unsupported"); }
                catch (OperationCanceledException) when (!stop.IsCancellationRequested) { }
                catch (IOException) { }
            }
        }
        async Task Updates()
        {
            while (!stop.IsCancellationRequested) { await engine.UpdateAsync(stop.Token); await Task.Delay(TimeSpan.FromHours(config.UpdateHours), stop.Token); }
        }
        async Task Processes()
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            while (!stop.IsCancellationRequested)
            {
                try
                {
                    string json = await AppControlWindows.RunAsync("$items=@(Get-CimInstance Win32_Process | Select-Object -First 2048); $names=@{}; foreach($p in $items){$names[[int]$p.ProcessId]=[string]$p.Name}; @($items | ForEach-Object {[pscustomobject]@{Pid=[int]$_.ProcessId;Created=[string]$_.CreationDate;Path=[string]$_.ExecutablePath;Command=[string]$_.CommandLine;Parent=[string]$names[[int]$_.ParentProcessId]}})");
                    var list = JsonSerializer.Deserialize<List<ObservedProcess>>(json) ?? [];
                    var active = new HashSet<string>(StringComparer.Ordinal);
                    foreach (var item in list)
                    {
                        string id = item.Pid + ":" + item.Created; active.Add(id);
                        if (seen.Contains(id) || string.IsNullOrEmpty(item.Path)) continue;
                        var alert = BehavioralSignals.Process(item.Path, item.Command, item.Parent, DateTimeOffset.UtcNow); if (alert is not null) engine.Alert(alert);
                    }
                    seen = active;
                }
                catch (Exception ex) { engine.Alert(new(DateTimeOffset.UtcNow, "Warning", "ProcessMonitorError", "Osservazione processi", ex.Message)); }
                await Task.Delay(TimeSpan.FromSeconds(20), stop.Token);
            }
        }
    }
}
internal sealed class AgentLifetimeLock : IDisposable
{
    readonly ManualResetEventSlim release = new(); readonly Thread owner; public bool Acquired { get; }
    public AgentLifetimeLock(string name)
    {
        var ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        owner = new Thread(() =>
        {
            try
            {
                using var mutex = new Mutex(false, name); bool acquired;
                try { acquired = mutex.WaitOne(TimeSpan.Zero); } catch (AbandonedMutexException) { acquired = true; }
                ready.SetResult(acquired); if (!acquired) return;
                try { release.Wait(); } finally { mutex.ReleaseMutex(); }
            }
            catch (Exception ex) { ready.TrySetException(ex); }
        }) { IsBackground = true, Name = "Sentinella lifetime lock" };
        owner.Start(); Acquired = ready.Task.GetAwaiter().GetResult();
    }
    public void Dispose() { release.Set(); owner.Join(); release.Dispose(); }
}
