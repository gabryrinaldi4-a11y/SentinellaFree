using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Sentinella.App;

/// <summary>
/// Read-only Windows protection inventory and explicitly requested, closed-list policy changes.
/// Configured Defender preferences are not proof of an effective protection layer, particularly
/// while Defender is passive. Never invoke ApplyPolicyAsync automatically at startup.
/// </summary>
public static class ProtectionTools
{
    private static readonly string[] Supported =
        ["ransomware-on", "ransomware-audit", "pua-on", "network-audit", "firewall-on"];

    public static IReadOnlyList<string> SupportedActions => Array.AsReadOnly(Supported);

    /// <summary>Checks an action without starting a process, elevating or changing settings.</summary>
    public static void ValidateAction(string action)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        if (!Supported.Contains(action, StringComparer.Ordinal))
            throw new ArgumentException("Azione di protezione non supportata.", nameof(action));
    }

    public static async Task<JsonElement> GetAuditAsync(CancellationToken cancellationToken = default)
    {
        var result = await RunReadOnlyAsync(AuditScript, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0)
            throw new IOException("Inventario Windows non disponibile: " + Limit(result.Output + " " + result.Error, 4000));
        using var document = JsonDocument.Parse(result.Output.Trim(), new JsonDocumentOptions { MaxDepth = 12 });
        return document.RootElement.Clone();
    }

    /// <summary>
    /// Requests Windows elevation for one fixed policy action. Completion confirms the configured
    /// setting, not antivirus efficacy. Refresh GetAuditAsync to inspect the effective Defender mode.
    /// UAC, organisation policy and tamper protection can prevent the change.
    /// </summary>
    public static async Task ApplyPolicyAsync(string action, CancellationToken cancellationToken = default)
    {
        ValidateAction(action);
        cancellationToken.ThrowIfCancellationRequested();
        string body = PolicyScript(action);
        string script = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; try { " + body +
            "; exit 0 } catch { exit 13 }";
        var info = new ProcessStartInfo(PowerShellPath())
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            Arguments = "-NoProfile -NonInteractive -EncodedCommand " + Encode(script)
        };
        Process? process;
        try
        {
            // UAC belongs to Windows; do not automate or bypass the consent dialog.
            process = await Task.Run(() => Process.Start(info)).ConfigureAwait(false);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            throw new OperationCanceledException("Richiesta di amministratore annullata in Windows: il comando non è stato avviato.", ex);
        }
        if (process is null) throw new IOException("Impossibile avviare la richiesta di amministratore.");
        using (process)
        using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            deadline.CancelAfter(TimeSpan.FromMinutes(2));
            try { await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false); }
            catch (OperationCanceledException ex)
            {
                // Do not kill an elevated settings process. It may already have applied the setting.
                throw new OperationCanceledException("Attesa interrotta: la modifica potrebbe essere già applicata. Aggiorna lo stato prima di riprovare.", ex);
            }
            if (process.ExitCode != 0)
                throw new IOException("Windows non ha confermato la modifica. Possibili cause: privilegi insufficienti, protezione antimanomissione, criteri dell'organizzazione o componente non disponibile. Aggiorna lo stato per verificare eventuali modifiche parziali.");
        }
    }

    private static string PolicyScript(string action) => action switch
    {
        "ransomware-on" => "Set-MpPreference -EnableControlledFolderAccess Enabled; if ([int](Get-MpPreference).EnableControlledFolderAccess -ne 1) { throw 'Not applied' }",
        "ransomware-audit" => "Set-MpPreference -EnableControlledFolderAccess AuditMode; if ([int](Get-MpPreference).EnableControlledFolderAccess -ne 2) { throw 'Not applied' }",
        "pua-on" => "Set-MpPreference -PUAProtection Enabled; if ([int](Get-MpPreference).PUAProtection -ne 1) { throw 'Not applied' }",
        "network-audit" => "Set-MpPreference -EnableNetworkProtection AuditMode; if ([int](Get-MpPreference).EnableNetworkProtection -ne 2) { throw 'Not applied' }",
        "firewall-on" => "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; if (@(Get-NetFirewallProfile | Where-Object {[int]$_.Enabled -ne 1}).Count -ne 0) { throw 'Not applied' }",
        _ => throw new ArgumentException("Azione di protezione non supportata.", nameof(action))
    };

    private static string PowerShellPath()
    {
        string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(path)) throw new FileNotFoundException("Windows PowerShell non disponibile.", path);
        return path;
    }
    private static string Encode(string script) => Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
    private static string Limit(string text, int length) => text.Length <= length ? text : text[..length] + "…";
    private record ReadResult(int ExitCode, string Output, string Error);

    private static async Task<ReadResult> RunReadOnlyAsync(string body, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        string script = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; " + body;
        var info = new ProcessStartInfo(PowerShellPath())
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
        };
        foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Encode(script) }) info.ArgumentList.Add(arg);
        using var process = new Process { StartInfo = info };
        if (!process.Start()) throw new IOException("Impossibile leggere le protezioni di Windows.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(90));
        try { await process.WaitForExitAsync(deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException)
        {
            try { process.Kill(true); } catch (InvalidOperationException) { }
            throw;
        }
        string stdout = await output.ConfigureAwait(false), stderr = await error.ConfigureAwait(false);
        if (stdout.Length > 8 * 1024 * 1024) throw new IOException("Inventario oltre il limite di rappresentazione.");
        return new(process.ExitCode, stdout, stderr);
    }

    private const string AuditScript = """
        function Clip([object]$Value, [int]$Max=4096) {
          if ($null -eq $Value) { return $null }
          $s=[string]$Value; if ($s.Length -gt $Max) { return $s.Substring(0,$Max) }; return $s
        }
        $d=[ordered]@{ObservedAt=[DateTimeOffset]::Now.ToString('o')}
        try {
          $s=Get-MpComputerStatus; $p=Get-MpPreference
          $updated=$null; if ($null -ne $s.AntivirusSignatureLastUpdated) {$updated=$s.AntivirusSignatureLastUpdated.ToString('o')}
          $d.Defender=[ordered]@{Available=$true; Values=[ordered]@{
            AntivirusEnabled=[bool]$s.AntivirusEnabled; RealTimeProtectionEnabled=[bool]$s.RealTimeProtectionEnabled
            BehaviorMonitorEnabled=[bool]$s.BehaviorMonitorEnabled; RunningMode=[string]$s.AMRunningMode
            SignatureVersion=[string]$s.AntivirusSignatureVersion; SignatureUpdated=$updated
            ControlledFolderAccess=[int]$p.EnableControlledFolderAccess; PuaProtection=[int]$p.PUAProtection
            NetworkProtection=[int]$p.EnableNetworkProtection; IsTamperProtected=[bool]$s.IsTamperProtected
          }; Note='Le preferenze configurate non provano che il livello sia operativo in modalita passiva.'}
        } catch { $d.Defender=[ordered]@{Available=$false; Error=(Clip $_.Exception.Message); Values=$null} }
        try {
          $raw=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -First 101)
          $items=@($raw | Select-Object -First 100 | ForEach-Object {[ordered]@{
            DisplayName=(Clip $_.displayName 256); ProductState=[int]$_.productState; ProductPath=(Clip $_.pathToSignedProductExe)
          }})
          $d.Providers=[ordered]@{Available=$true; Items=$items; Truncated=($raw.Count -gt 100); Note='Registrazione Windows: non certifica lo stato effettivo di ogni motore.'}
        } catch { $d.Providers=[ordered]@{Available=$false; Error=(Clip $_.Exception.Message); Items=@(); Truncated=$false} }
        try {
          $items=@(Get-NetFirewallProfile | Select-Object -First 10 | ForEach-Object {[ordered]@{
            Name=[string]$_.Name; Enabled=([int]$_.Enabled -eq 1)
            DefaultInboundAction=[string]$_.DefaultInboundAction; DefaultOutboundAction=[string]$_.DefaultOutboundAction
          }})
          $d.Firewall=[ordered]@{Available=$true; Items=$items}
        } catch { $d.Firewall=[ordered]@{Available=$false; Error=(Clip $_.Exception.Message); Items=@()} }
        try {
          $raw=@(Get-CimInstance Win32_StartupCommand | Select-Object -First 501)
          $items=@($raw | Select-Object -First 500 | ForEach-Object {[ordered]@{
            Name=(Clip $_.Name 256); Command=(Clip $_.Command); Location=(Clip $_.Location 1024); User=(Clip $_.User 256)
          }})
          $d.Startup=[ordered]@{Available=$true; Items=$items; Truncated=($raw.Count -gt 500); Note='Inventario: una voce di avvio non dimostra una minaccia.'}
        } catch { $d.Startup=[ordered]@{Available=$false; Error=(Clip $_.Exception.Message); Items=@(); Truncated=$false} }
        try {
          $raw=@(Get-NetTCPConnection | Select-Object -First 501)
          $names=@{}; $items=@($raw | Select-Object -First 500 | ForEach-Object {
            $owner=[int]$_.OwningProcess
            if (-not $names.ContainsKey($owner)) {
              $n=$null; try {$n=(Get-Process -Id $owner -ErrorAction Stop).ProcessName} catch {}
              $names[$owner]=$n
            }
            [ordered]@{LocalAddress=[string]$_.LocalAddress; LocalPort=[int]$_.LocalPort
              RemoteAddress=[string]$_.RemoteAddress; RemotePort=[int]$_.RemotePort; State=[string]$_.State
              ProcessId=$owner; ProcessName=$names[$owner]}
          })
          $d.Connections=[ordered]@{Available=$true; Items=$items; Truncated=($raw.Count -gt 500); Note='Snapshot TCP locale, senza cattura traffico o classificazione reputazione.'}
        } catch { $d.Connections=[ordered]@{Available=$false; Error=(Clip $_.Exception.Message); Items=@(); Truncated=$false} }
        $d | ConvertTo-Json -Depth 8 -Compress
        """;
}
