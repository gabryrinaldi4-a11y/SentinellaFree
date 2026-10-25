using System.Security.Cryptography;
using System.Xml.Linq;
using System.Text.Json;
using Sentinella.Core;
using Sentinella.Desktop;

int passed = 0;
void Check(bool condition, string name) { if (!condition) throw new Exception("FAIL: " + name); Console.WriteLine("PASS: " + name); passed++; }
void Reject(Action action, string name) { try { action(); } catch (ArgumentException) { Check(true, name); return; } catch (System.Xml.XmlException) { Check(true, name); return; } throw new Exception("FAIL: " + name); }
var app = new ApprovedApplication(@"C:\Users\test\O'Brien & esempio.exe", "O'Brien & esempio.exe", new string('A',64), 1000,
    "0x" + new string('B',64), "O'Brien & esempio.exe", 1000, DateTimeOffset.UtcNow);
var plan = new AppControlDraft(Guid.NewGuid(), "S-1-5-21-1-2-3-1001", [app]);
string audit = AppControlPolicy.Build(plan); string block = AppControlPolicy.Build(plan, true);
var xml = XDocument.Parse(block); var exe = xml.Root!.Elements("RuleCollection").Single(x => (string?)x.Attribute("Type") == "Exe");
Check(XDocument.Parse(audit).Descendants("RuleCollection").First().Attribute("EnforcementMode")!.Value == "AuditOnly", "authoring defaults to audit");
Check((string?)exe.Attribute("EnforcementMode") == "Enabled", "explicit block candidate");
Check(exe.Elements().Where(x => (string?)x.Attribute("Action") == "Deny").All(x => (string?)x.Attribute("UserOrGroupSid") == plan.UserSid), "denials target only selected user");
Check(exe.Elements().Count(x => (string?)x.Attribute("Action") == "Allow") == 1, "other users preserve allow baseline");
Check(exe.Descendants("FileHash").All(h => (string?)h.Attribute("Data") == app.AppLockerHash), "Windows Authenticode hash used, never flat SHA fallback");
Check(!exe.Descendants("FilePathCondition").Any(c => (string?)c.Attribute("Path") == @"%PROGRAMFILES%\*"), "Program Files is not implicitly approved in strict profile");
Check(XDocument.Parse(AppControlPolicy.Build(plan with { AllowProgramFiles = true })).Descendants("FilePathCondition").Any(c => (string?)c.Attribute("Path") == @"%PROGRAMFILES%\*"), "less restrictive base requires opt-in");
Check(exe.Elements().Where(x => (string?)x.Attribute("Action") == "Deny").All(x => x.Descendants("FileHash").Count() == 1), "approval exception added to every denial");
Check(!XDocument.Parse(AppControlPolicy.Build(plan with { Applications = [] })).Descendants("FileHash").Any(), "revocation removes all hash exceptions");
Check(xml.Descendants("RuleCollection").Any(x => (string?)x.Attribute("Type") == "Appx"), "packaged-app compatibility collection retained");
Check(!xml.Descendants("RuleCollection").Any(x => (string?)x.Attribute("Type") is "Dll" or "Script" or "Msi"), "does not claim DLL script or installer coverage");
Check(xml.Descendants("FileHash").First().Attribute("SourceFileName")!.Value == app.AppLockerName, "XML escaping preserves names");
Reject(() => AppControlPolicy.Build(plan with { UserSid = "S-1-1-0" }), "reject global target");
Reject(() => AppControlPolicy.Build(plan with { Applications = [app with { AppLockerHash = new string('A',64) }] }), "reject flat hash supplied as AppLocker hash");
Reject(() => AppControlPolicy.Build(plan with { Applications = [app with { Path = @"C:\test.exe:stream" }] }), "reject alternate streams");
Reject(() => AppControlPolicy.Build(plan with { Applications = [app with { Path = @"\\server\share\test.exe" }] }), "reject UNC paths");
Reject(() => AppControlPolicy.Build(plan with { Applications = [app, app] }), "reject duplicate approval");
Reject(() => AppControlPolicy.Build(plan with { Applications = [app with { Length = 0 }] }), "reject missing length");
Reject(() => AppControlPolicy.ReadWindowsHash(app.Path, app.Name, app.Sha256, app.Length, "<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///C:/private'>]><AppLockerPolicy>&e;</AppLockerPolicy>"), "reject XML DTD");
Check(AppControlPolicy.Fingerprint(block) == AppControlPolicy.Fingerprint(XDocument.Parse(block).ToString(SaveOptions.DisableFormatting)), "policy fingerprints ignore formatting");
Check(AppControlPolicy.Fingerprint(audit) != AppControlPolicy.Fingerprint(block), "audit and blocking fingerprints differ");
string temp = Path.Combine(Path.GetTempPath(), "Sentinella-AppControlTests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temp);
try
{
    string store = Path.Combine(temp, "draft.json"); AppControlPolicy.Save(store, plan);
    var loaded = AppControlPolicy.Load(store, plan.UserSid); Check(loaded.Id == plan.Id && loaded.Applications.Single().Sha256 == app.Sha256, "approval draft round trip");
    try { AppControlPolicy.Load(store, "S-1-5-21-1-2-3-1002"); throw new Exception("foreign user accepted"); } catch (IOException) { Check(true, "reject foreign user draft"); }
    if (args.Contains("--native"))
    {
        // Copy already-trusted Windows binaries as benign file fixtures. Never execute these copies.
        string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        string approved = Path.Combine(temp, "approved O'Brien & [α] esempio.exe"), unknown = Path.Combine(temp, "unapproved.exe");
        File.Copy(Path.Combine(system, "WindowsPowerShell", "v1.0", "powershell.exe"), approved);
        File.Copy(Path.Combine(system, "cmd.exe"), unknown);
        var nativeApproval = await AppControlWindows.InspectFileAsync(approved);
        var nativePlan = new AppControlDraft(Guid.NewGuid(), AppControlWindows.UserSid, [nativeApproval]);
        async Task<string> Decision(AppControlDraft p, string path, string? user = null)
        {
            using var result = JsonDocument.Parse(await AppControlWindows.EvaluateAsync(p, path, user));
            var row = result.RootElement.ValueKind == JsonValueKind.Array ? result.RootElement[0] : result.RootElement;
            return row.GetProperty("Decision").GetString()!;
        }
        Check(await Decision(nativePlan, approved) == "Allowed", "Windows permits approved Authenticode hash outside trusted directories");
        Check((await Decision(nativePlan, unknown)).StartsWith("Denied", StringComparison.Ordinal), "Windows denies unapproved executable before policy installation");
        Check((await Decision(nativePlan with { Applications = [] }, approved)).StartsWith("Denied", StringComparison.Ordinal), "Windows denies revoked version");
        Check(await Decision(nativePlan, Path.Combine(system, "cmd.exe")) == "Allowed", "Windows recovery tools remain allowed");
        var foreign = nativePlan with { UserSid = "S-1-5-21-1-2-3-1002" };
        Check(await Decision(foreign, unknown, AppControlWindows.UserSid) == "Allowed", "policy does not deny another user");
        string mutable = Path.Combine(temp, "changed.exe"); File.Copy(unknown, mutable);
        Check((await Decision(nativePlan, mutable)).StartsWith("Denied", StringComparison.Ordinal), "renaming unapproved bytes does not approve them");
    }
    Console.WriteLine($"RESULT: {passed} checks passed. No policy installed, no elevation, no service changes, no fixture executed.");
}
finally { Directory.Delete(temp, true); }
