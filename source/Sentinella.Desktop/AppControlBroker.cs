using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Sentinella.Core;
namespace Sentinella.Desktop;

internal static class AppControlBroker
{
    sealed record SavedPolicy(Guid PlanId, string UserSid, string OriginalXml, string OriginalStartType,
        string LastLocalStamp, string? AuditedPlanStamp, bool Active);
    static string Root => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinellaFree.AppControl");
    static string StatePath => Path.Combine(Root, "state.json");
    static string OriginalPath => Path.Combine(Root, "original-policy.xml");
    static void EnsureProtectedDirectory()
    {
        AppControlWindows.ValidatePath(Root);
        var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
        if (!Directory.Exists(Root))
        {
            var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false); acl.SetOwner(admin);
            foreach (var sid in new[] { admin, system }) acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(users, FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(Root).Create(acl);
        }
        var current = new DirectoryInfo(Root).GetAccessControl();
        string owner = current.GetOwner(typeof(SecurityIdentifier))?.Value ?? throw new IOException("Proprietario archivio non disponibile.");
        if (!current.AreAccessRulesProtected || (owner != admin.Value && owner != system.Value)) throw new IOException("Archivio criteri non protetto: operazione rifiutata.");
        foreach (FileSystemAccessRule rule in current.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            string sid = rule.IdentityReference.Value;
            if (rule.AccessControlType != AccessControlType.Allow ||
                (sid != admin.Value && sid != system.Value && sid != users.Value) ||
                (sid == users.Value && (rule.FileSystemRights & ~(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize)) != 0))
                throw new IOException("Permessi inattesi nell'archivio criteri: operazione rifiutata.");
        }
        foreach (string file in new[] { StatePath, OriginalPath })
        {
            AppControlWindows.ValidatePath(file);
            if (!File.Exists(file)) continue;
            var acl = new FileInfo(file).GetAccessControl();
            if (acl.GetOwner(typeof(SecurityIdentifier))?.Value is not ("S-1-5-18" or "S-1-5-32-544")) throw new IOException("Proprietario inatteso del backup criteri.");
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544") &&
                    (rule.FileSystemRights & ~(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize)) != 0)
                    throw new IOException("Backup criteri modificabile da utenti non amministratori.");
        }
    }
    static void SaveState(SavedPolicy state)
    {
        string temp = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".tmp");
        try { File.WriteAllText(temp, JsonSerializer.Serialize(state), new UTF8Encoding(false)); File.Move(temp, StatePath, true); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    static bool HasRules(string xml) => XDocument.Parse(xml).Descendants().Any(e => e.Name.LocalName.EndsWith("Rule", StringComparison.Ordinal));
    static async Task SetPolicy(string xml)
    {
        string path = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".xml");
        try { File.WriteAllText(path, xml, new UTF8Encoding(false)); await AppControlWindows.RunAsync("Set-AppLockerPolicy -XmlPolicy " + AppControlWindows.Literal(path) + "; 'configured'", false); }
        finally { File.Delete(path); }
    }
    static async Task ConfigureService(string startType)
    {
        string native = startType switch { "Automatic" => "auto", "Manual" => "demand", "Disabled" => "disabled", _ => throw new IOException("Avvio servizio non riconosciuto.") };
        await AppControlWindows.RunAsync("$sc=Join-Path $env:SystemRoot 'System32\\sc.exe'; $output=& $sc config AppIDSvc start= " + native +
            "; if($LASTEXITCODE -ne 0){throw ($output -join ' ')}; 'configured'", false);
    }
    public static async Task RunElevatedAsync(string requestPath, string expectedHash)
    {
        if (!AppControlWindows.IsAdministrator) throw new IOException("Sono necessari i permessi amministratore approvati in Windows.");
        if (!System.Text.RegularExpressions.Regex.IsMatch(expectedHash, "^[A-Fa-f0-9]{64}$")) throw new IOException("Richiesta non valida.");
        AppControlWindows.ValidatePath(requestPath);
        AppControlRequest request;
        using (var input = new FileStream(requestPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            if (input.Length > 1024 * 1024) throw new IOException("Richiesta oltre il limite.");
            using var bytes = new MemoryStream(); await input.CopyToAsync(bytes);
            if (!Convert.ToHexString(SHA256.HashData(bytes.ToArray())).Equals(expectedHash, StringComparison.OrdinalIgnoreCase)) throw new IOException("La richiesta e cambiata prima dell'autorizzazione.");
            request = JsonSerializer.Deserialize<AppControlRequest>(bytes.ToArray()) ?? throw new IOException("Richiesta vuota.");
        }
        AppControlPolicy.Validate(request.Draft);
        if (request.Action is not ("Audit" or "Enforce" or "Restore")) throw new IOException("Azione non supportata.");
        using var mutex = new Mutex(false, @"Global\SentinellaFree.AppControl");
        bool acquired; try { acquired = mutex.WaitOne(TimeSpan.Zero); } catch (AbandonedMutexException) { acquired = true; }
        if (!acquired) throw new IOException("Un'altra modifica AppLocker e in corso.");
        try { await Change(request); } finally { mutex.ReleaseMutex(); }
    }
    static async Task Change(AppControlRequest request)
    {
        var status = await AppControlWindows.InspectAsync();
        if (status.LocalXml is null) throw new IOException("Impossibile leggere il criterio locale: nessuna modifica applicata.");
        string localStamp = AppControlPolicy.Fingerprint(status.LocalXml);
        if (status.Stamp != request.ExpectedStamp || status.Stamp != localStamp)
            throw new IOException("Criteri cambiati o gestiti esternamente: aggiorna lo stato. Nessun criterio esterno viene sovrascritto.");
        EnsureProtectedDirectory();
        SavedPolicy? saved = File.Exists(StatePath) ? JsonSerializer.Deserialize<SavedPolicy>(File.ReadAllText(StatePath)) : null;
        if (saved is { Active: true })
        {
            if (saved.PlanId != request.Draft.Id || saved.UserSid != request.Draft.UserSid || saved.LastLocalStamp != localStamp)
                throw new IOException("Il criterio corrente non corrisponde a quello gestito da questa bozza. Ripristino automatico rifiutato.");
        }
        else
        {
            if (request.Action == "Restore") throw new IOException("Nessun criterio Sentinella attivo da ripristinare.");
            if (HasRules(status.LocalXml) || HasRules(status.EffectiveXml)) throw new IOException("AppLocker ha gia regole: questa versione non le sostituisce e non le unisce.");
            saved = new(request.Draft.Id, request.Draft.UserSid, status.LocalXml, status.StartType, localStamp, null, false);
            File.WriteAllText(OriginalPath, status.LocalXml, new UTF8Encoding(false)); SaveState(saved);
        }
        if (request.Action == "Restore")
        {
            if (!File.Exists(OriginalPath) || AppControlPolicy.Fingerprint(File.ReadAllText(OriginalPath)) != AppControlPolicy.Fingerprint(saved!.OriginalXml))
                throw new IOException("Backup originale assente o incoerente.");
            await SetPolicy(saved.OriginalXml);
            var restored = await AppControlWindows.InspectAsync();
            if (restored.LocalXml is null || AppControlPolicy.Fingerprint(restored.LocalXml) != AppControlPolicy.Fingerprint(saved.OriginalXml))
                throw new IOException("Windows non ha confermato il ripristino. Backup: " + OriginalPath);
            await ConfigureService(saved.OriginalStartType);
            SaveState(saved with { Active = false, LastLocalStamp = restored.Stamp, AuditedPlanStamp = null });
            return; // Do not stop a shared Windows service.
        }
        string auditStamp = AppControlPolicy.Fingerprint(AppControlPolicy.Build(request.Draft));
        if (request.Action == "Enforce" && saved!.AuditedPlanStamp != auditStamp)
            throw new IOException("Applica e verifica prima l'audit della stessa lista di autorizzazioni.");
        var handles = new List<FileStream>();
        string beforeXml = status.LocalXml;
        bool serviceChanged = false, installAttempted = false;
        string candidate = AppControlPolicy.Build(request.Draft, request.Action == "Enforce");
        string candidateStamp = AppControlPolicy.Fingerprint(candidate);
        try
        {
            foreach (var app in request.Draft.Applications)
            {
                AppControlWindows.ValidatePath(app.Path);
                handles.Add(new FileStream(app.Path, FileMode.Open, FileAccess.Read, FileShare.Read));
                var actual = await AppControlWindows.InspectFileAsync(app.Path);
                if (!actual.Sha256.Equals(app.Sha256, StringComparison.OrdinalIgnoreCase) || actual.Length != app.Length ||
                    !actual.AppLockerHash.Equals(app.AppLockerHash, StringComparison.OrdinalIgnoreCase) || actual.AppLockerLength != app.AppLockerLength)
                    throw new IOException("File cambiato: riesamina e autorizza la nuova versione. " + app.Path);
            }
            string ownHash; using (var own = File.OpenRead(AppControlWindows.OwnExecutable)) ownHash = Convert.ToHexString(SHA256.HashData(own));
            if (!request.Draft.Applications.Any(a => a.Sha256.Equals(ownHash, StringComparison.OrdinalIgnoreCase)))
                throw new IOException("Aggiungi esplicitamente questa versione di Sentinella alle autorizzazioni prima dell'attivazione.");
            foreach (string recovery in new[] { AppControlWindows.OwnExecutable, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe") })
            {
                string verdict = await AppControlWindows.EvaluateAsync(request.Draft, recovery);
                using var result = JsonDocument.Parse(verdict);
                var entries = result.RootElement.ValueKind == JsonValueKind.Array ? result.RootElement.EnumerateArray().ToArray() : [result.RootElement];
                if (entries.Length != 1 || entries[0].GetProperty("Decision").GetString() != "Allowed")
                    throw new IOException("La verifica di recupero non consente un componente necessario: " + recovery);
            }
            // Recheck the lease immediately before changing native state.
            var latest = await AppControlWindows.InspectAsync();
            if (latest.Stamp != status.Stamp || latest.LocalXml is null || AppControlPolicy.Fingerprint(latest.LocalXml) != localStamp)
                throw new IOException("Criterio cambiato durante la verifica: nessuna modifica applicata.");
            if (status.StartType != "Automatic") { await ConfigureService("Automatic"); serviceChanged = true; }
            await AppControlWindows.RunAsync("Start-Service AppIDSvc; if((Get-Service AppIDSvc).Status -ne 'Running'){throw 'Application Identity not running'}; 'running'", false);
            installAttempted = true; await SetPolicy(candidate);
            var after = await AppControlWindows.InspectAsync();
            if (after.LocalXml is null || AppControlPolicy.Fingerprint(after.LocalXml) != candidateStamp || after.Stamp != candidateStamp || after.Service != "Running")
                throw new IOException("Windows non ha confermato il criterio e il servizio attesi.");
            SaveState(saved! with { LastLocalStamp = candidateStamp, Active = true, AuditedPlanStamp = auditStamp });
        }
        catch
        {
            // Restore only if native state still equals our candidate; never overwrite an external change.
            var current = await AppControlWindows.InspectAsync();
            if (installAttempted && current.LocalXml is not null && AppControlPolicy.Fingerprint(current.LocalXml) == candidateStamp) await SetPolicy(beforeXml);
            if (serviceChanged) await ConfigureService(status.StartType);
            throw;
        }
        finally { foreach (var handle in handles) handle.Dispose(); }
    }
}
