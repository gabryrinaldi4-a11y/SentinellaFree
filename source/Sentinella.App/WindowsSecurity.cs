using System.Diagnostics;
using System.Text;
using System.Text.Json;
namespace Sentinella.App;
public record CommandResult(int ExitCode, string Output, string StandardError = "");
public static class WindowsSecurity
{
    public static async Task<CommandResult> RunAsync(string executable, IEnumerable<string> arguments,
        CancellationToken cancellationToken = default, TimeSpan? timeout = null)
    {
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8 };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = new Process { StartInfo = info };
        if (!process.Start()) throw new IOException("Impossibile avviare il comando.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout ?? TimeSpan.FromMinutes(30));
        try { await process.WaitForExitAsync(deadline.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(true); } catch (InvalidOperationException) { }
            throw new OperationCanceledException("Comando interrotto o tempo massimo superato. Una scansione Defender avviata dal servizio può continuare: verificarla in Sicurezza di Windows.");
        }
        return new(process.ExitCode, await stdout, await stderr);
    }
    static Task<CommandResult> PowerShellAsync(string script, CancellationToken token)
    {
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");
        var preamble = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; ";
        return RunAsync(executable, ["-NoProfile", "-NonInteractive", "-EncodedCommand",
            Convert.ToBase64String(Encoding.Unicode.GetBytes(preamble + script))], token, TimeSpan.FromSeconds(60));
    }
    public static async Task<JsonElement> StatusAsync(CancellationToken token = default)
    {
        const string script = """
            $s=Get-MpComputerStatus; $p=Get-MpPreference;
            $f=@(Get-NetFirewallProfile | Select-Object Name,@{Name='Enabled';Expression={[int]$_.Enabled -eq 1}});
            [pscustomobject]@{
              AntivirusEnabled=$s.AntivirusEnabled; RealTimeProtectionEnabled=$s.RealTimeProtectionEnabled;
              BehaviorMonitorEnabled=$s.BehaviorMonitorEnabled; IoavProtectionEnabled=$s.IoavProtectionEnabled;
              AMRunningMode=$s.AMRunningMode; AntivirusSignatureVersion=$s.AntivirusSignatureVersion;
              SignatureUpdated=$s.AntivirusSignatureLastUpdated.ToString('o');
              ControlledFolderAccess=[int]$p.EnableControlledFolderAccess;
              Firewall=$f; ObservedAt=(Get-Date).ToString('o')
            } | ConvertTo-Json -Depth 5 -Compress
            """;
        var result = await PowerShellAsync(script, token);
        if (result.ExitCode != 0) throw new IOException(result.Output + result.StandardError);
        using var doc = JsonDocument.Parse(result.Output.Trim());
        return doc.RootElement.Clone();
    }
    public static async Task<string> AuditAsync(CancellationToken token = default)
    {
        const string script = """
            $startup=@(Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User);
            $av=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName,pathToSignedProductExe,productState);
            [pscustomobject]@{ObservedAt=(Get-Date).ToString('o'); Startup=$startup; AntivirusProviders=$av;
              Note='Inventario informativo: una voce di avvio non dimostra una minaccia.'} | ConvertTo-Json -Depth 5
            """;
        var result = await PowerShellAsync(script, token);
        if (result.ExitCode != 0) throw new IOException(result.Output + result.StandardError);
        return result.Output;
    }
    public static string DefenderExecutable()
    {
        var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        if (Directory.Exists(platform))
        {
            foreach (var dir in Directory.GetDirectories(platform).OrderByDescending(Path.GetFileName, StringComparer.OrdinalIgnoreCase))
            {
                var path = Path.Combine(dir, "MpCmdRun.exe");
                if (File.Exists(path)) return path;
            }
        }
        var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        if (File.Exists(fallback)) return fallback;
        throw new FileNotFoundException("Microsoft Defender non è disponibile su questo sistema.");
    }
    public static Task<CommandResult> ScanAsync(string? target, int type, CancellationToken token)
    {
        List<string> args = ["-Scan", "-ScanType", type.ToString(System.Globalization.CultureInfo.InvariantCulture)];
        if (type == 3)
        {
            if (string.IsNullOrWhiteSpace(target) || (!File.Exists(target) && !Directory.Exists(target)))
                throw new IOException("Seleziona un file o una cartella esistente.");
            args.AddRange(["-File", Path.GetFullPath(target), "-DisableRemediation"]);
        }
        return RunAsync(DefenderExecutable(), args, token, TimeSpan.FromHours(type == 2 ? 24 : 2));
    }
    public static Task<CommandResult> UpdateAsync(CancellationToken token) =>
        RunAsync(DefenderExecutable(), ["-SignatureUpdate"], token, TimeSpan.FromMinutes(15));
    public static void OpenSecurity(string section = "") =>
        Process.Start(new ProcessStartInfo("windowsdefender:" + section) { UseShellExecute = true });
}


