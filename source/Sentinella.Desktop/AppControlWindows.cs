using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Sentinella.Core;
namespace Sentinella.Desktop;

public sealed record AppControlStatus(string EffectiveXml, string? LocalXml, string Service, string StartType, string SmartAppControl, string? LocalError)
{
    public string Stamp => AppControlPolicy.Fingerprint(EffectiveXml);
    public string Mode { get { var xml = System.Xml.Linq.XDocument.Parse(EffectiveXml); return (string?)xml.Root?.Elements("RuleCollection")
        .FirstOrDefault(e => (string?)e.Attribute("Type") == "Exe")?.Attribute("EnforcementMode") ?? "Non configurato"; } }
}
public sealed record AppControlRequest(string Action, AppControlDraft Draft, string ExpectedStamp);

internal static class AppControlWindows
{
    public static string OwnExecutable => Path.Combine(AppContext.BaseDirectory, "SentinellaFree.exe");
    public static string UserSid => WindowsIdentity.GetCurrent().User?.Value ?? throw new IOException("Utente Windows non disponibile.");
    public static bool IsAdministrator => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    internal static string Literal(string value) => "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + Convert.ToBase64String(Encoding.UTF8.GetBytes(value)) + "')))";
    public static void ValidatePath(string path)
    {
        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.Length < 3 || path[1] != ':' || path[2..].Contains(':'))
            throw new IOException("Serve un percorso locale senza stream alternativi.");
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Collegamenti e reparse point non supportati: " + current);
    }
    public static async Task<string> RunAsync(string command, bool readOnly = true)
    {
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        var info = new ProcessStartInfo(executable) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8, StandardInputEncoding = new UTF8Encoding(false) };
        info.WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
        info.Environment["PSModulePath"] = Path.Combine(info.WorkingDirectory, "WindowsPowerShell", "v1.0", "Modules");
        info.Environment["PATH"] = info.WorkingDirectory;
        info.Environment["SystemRoot"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        info.Environment["WINDIR"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        info.Environment.Remove("PSExecutionPolicyPreference");
        foreach (string arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-" }) info.ArgumentList.Add(arg);
        using var process = Process.Start(info) ?? throw new IOException("Windows PowerShell non disponibile.");
        var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
        string script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; try { $result = & { " + command +
            " }; $bytes=[Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 12 -Compress)); [Console]::WriteLine('SF_RESULT:'+ [Convert]::ToBase64String($bytes)); exit 0 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 13 }";
        await process.StandardInput.WriteLineAsync(script); process.StandardInput.Close();
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(100)); }
        catch (TimeoutException) { if (readOnly) { try { process.Kill(true); } catch (InvalidOperationException) { } } throw new IOException("Attesa Windows scaduta. Per una modifica, aggiorna lo stato prima di riprovare."); }
        string output = await stdout, error = await stderr;
        if (output.Length > 4 * 1024 * 1024 || error.Length > 65536) throw new IOException("Risposta Windows oltre il limite.");
        if (process.ExitCode != 0) throw new IOException("Windows: " + error.Trim());
        string? line = output.Split('\n').LastOrDefault(x => x.StartsWith("SF_RESULT:", StringComparison.Ordinal));
        if (line is null) throw new IOException("Risposta Windows non valida.");
        return Encoding.UTF8.GetString(Convert.FromBase64String(line[10..].Trim()));
    }
    public static async Task<AppControlStatus> InspectAsync()
    {
        string json = await RunAsync("$local=$null; $problem=$null; try {$local=Get-AppLockerPolicy -Local -Xml} catch {$problem=$_.Exception.Message}; " +
            "$effective=Get-AppLockerPolicy -Effective -Xml; $svc=Get-Service AppIDSvc; $sac='Unknown'; try {$sac=[string](Get-MpComputerStatus).SmartAppControlState} catch {}; " +
            "[pscustomobject]@{EffectiveXml=[string]$effective; LocalXml=$local; Service=[string]$svc.Status; StartType=[string]$svc.StartType; SmartAppControl=$sac; LocalError=$problem}");
        return JsonSerializer.Deserialize<AppControlStatus>(json) ?? throw new IOException("Stato AppLocker vuoto.");
    }
    public static async Task<ApprovedApplication> InspectFileAsync(string path)
    {
        path = Path.GetFullPath(path); ValidatePath(path);
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, true);
        if (stream.Length > 512L * 1024 * 1024) throw new IOException("Eseguibile oltre il limite di 512 MiB.");
        string raw = Convert.ToHexString(await SHA256.HashDataAsync(stream));
        string xmlJson = await RunAsync("$file=Get-AppLockerFileInformation -Path ([WildcardPattern]::Escape(" + Literal(path) + ")); New-AppLockerPolicy -FileInformation $file -RuleType Hash -User " + Literal(UserSid) + " -Xml");
        string xml = JsonSerializer.Deserialize<string>(xmlJson) ?? throw new IOException("Hash Windows vuoto.");
        return AppControlPolicy.ReadWindowsHash(path, Path.GetFileName(path), raw, stream.Length, xml);
    }
    public static async Task<string> EvaluateAsync(AppControlDraft draft, string path, string? evaluationUserSid = null)
    {
        AppControlPolicy.Validate(draft); AppControlPolicy.Validate(draft with { UserSid = evaluationUserSid ?? draft.UserSid }); path = Path.GetFullPath(path); ValidatePath(path);
        string temp = Path.Combine(Path.GetTempPath(), "Sentinella-evaluate-" + Guid.NewGuid().ToString("N") + ".xml");
        try
        {
            // Offline rule test: does not install the policy, start an executable or alter services.
            File.WriteAllText(temp, AppControlPolicy.Build(draft, true), new UTF8Encoding(false));
            string json = await RunAsync("@(Test-AppLockerPolicy -XmlPolicy " + Literal(temp) + " -Path ([WildcardPattern]::Escape(" + Literal(path) + ")) -User " + Literal(evaluationUserSid ?? draft.UserSid) +
                " | ForEach-Object {[pscustomobject]@{Path=[string]$_.FilePath; Decision=[string]$_.PolicyDecision}})");
            return json;
        }
        finally { File.Delete(temp); }
    }
    public static async Task RequestChangeAsync(AppControlRequest request)
    {
        AppControlPolicy.Validate(request.Draft);
        if (request.Action is not ("Audit" or "Enforce" or "Restore")) throw new ArgumentException("Azione non supportata.");
        string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinellaFree", "requests");
        Directory.CreateDirectory(folder); ValidatePath(folder);
        string path = Path.Combine(folder, Guid.NewGuid().ToString("N") + ".json");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(request); string sha = Convert.ToHexString(SHA256.HashData(bytes));
        File.WriteAllBytes(path, bytes);
        try
        {
            var start = new ProcessStartInfo(OwnExecutable) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory };
            start.Arguments = "--app-control-admin \"" + path + "\" " + sha;
            using var process = Process.Start(start) ?? throw new IOException("Richiesta amministratore non avviata.");
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromMinutes(5)); }
            catch (TimeoutException) { throw new IOException("La finestra amministratore potrebbe essere ancora attiva. Non ripetere la modifica prima di aver aggiornato lo stato."); }
            if (process.ExitCode != 0) throw new IOException("Windows non ha confermato la modifica. Leggi il messaggio nella finestra amministratore e aggiorna lo stato.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { throw new OperationCanceledException("Autorizzazione Windows annullata; nessuna azione avviata.", ex); }
        finally { File.Delete(path); }
    }
}
