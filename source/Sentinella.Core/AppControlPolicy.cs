using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
namespace Sentinella.Core;

public sealed record ApprovedApplication(string Path, string Name, string Sha256, long Length,
    string AppLockerHash, string AppLockerName, long AppLockerLength, DateTimeOffset ApprovedAt);
public sealed record AppControlDraft(Guid Id, string UserSid, List<ApprovedApplication> Applications, bool AllowProgramFiles = false);

/// <summary>Policy authoring only. No process execution, elevation or policy installation.</summary>
public static class AppControlPolicy
{
    public const int MaximumApplications = 128;
    public static IReadOnlyList<string> BasePaths { get; } = Array.AsReadOnly(new[] { @"%WINDIR%\*" });
    public static readonly string[] RestrictedWindowsPaths = [@"%WINDIR%\Temp\*", @"%WINDIR%\Tasks\*",
        @"%WINDIR%\System32\Tasks\*", @"%WINDIR%\System32\spool\drivers\color\*", @"%WINDIR%\tracing\*"];
    public static void Validate(AppControlDraft draft)
    {
        if (draft.Id == Guid.Empty || !Regex.IsMatch(draft.UserSid ?? "", @"^S-1-5-21-\d+-\d+-\d+-\d+$"))
            throw new ArgumentException("Utente locale o dominio non valido.");
        if (draft.Applications is null || draft.Applications.Count > MaximumApplications)
            throw new ArgumentException("Numero di autorizzazioni oltre il limite.");
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var app in draft.Applications)
        {
            if (app is null || string.IsNullOrWhiteSpace(app.Path) || app.Path.Length > 1024 ||
                !Regex.IsMatch(app.Path, @"^[A-Za-z]:\\") || app.Path[2..].Contains(':') ||
                !(app.Path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || app.Path.EndsWith(".com", StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException("Solo eseguibili su percorsi locali senza stream alternativi.");
            if (!Regex.IsMatch(app.Sha256 ?? "", @"^[A-Fa-f0-9]{64}$") ||
                !Regex.IsMatch(app.AppLockerHash ?? "", @"^0x[A-Fa-f0-9]{64}$") || app.Length <= 0 || app.AppLockerLength <= 0)
                throw new ArgumentException("Hash o dimensione non validi. L'hash AppLocker deve provenire da Windows.");
            if (string.IsNullOrWhiteSpace(app.Name) || app.Name.Length > 200 ||
                string.IsNullOrWhiteSpace(app.AppLockerName) || app.AppLockerName.Length > 200 ||
                app.AppLockerName.Any(c => char.IsControl(c) || c is '\\' or '/'))
                throw new ArgumentException("Nome del file non valido.");
            if (!hashes.Add(app.AppLockerHash!)) throw new ArgumentException("Versione gia autorizzata.");
        }
    }
    public static XElement HashCondition(ApprovedApplication app) => new("FileHashCondition",
        new XElement("FileHash", new XAttribute("Type", "SHA256"), new XAttribute("Data", app.AppLockerHash.ToUpperInvariant().Replace("0X", "0x")),
            new XAttribute("SourceFileName", app.AppLockerName), new XAttribute("SourceFileLength", app.AppLockerLength)));
    static string RuleId(Guid id, string key) => new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(id.ToString("D") + ":" + key))[..16]).ToString("D");
    static XElement PathRule(AppControlDraft draft, string key, string sid, string action, string path, IEnumerable<XElement>? exceptions = null)
    {
        var rule = new XElement("FilePathRule", new XAttribute("Id", RuleId(draft.Id, key)),
            new XAttribute("Name", "Sentinella: " + key), new XAttribute("Description", "Sentinella application control; EXE/COM only"),
            new XAttribute("UserOrGroupSid", sid), new XAttribute("Action", action),
            new XElement("Conditions", new XElement("FilePathCondition", new XAttribute("Path", path))));
        var list = exceptions?.ToList(); if (list is { Count: > 0 }) rule.Add(new XElement("Exceptions", list));
        return rule;
    }
    public static string Build(AppControlDraft draft, bool enforce = false)
    {
        Validate(draft);
        var hashes = draft.Applications.OrderBy(x => x.AppLockerHash, StringComparer.OrdinalIgnoreCase).Select(HashCondition).ToList();
        // Explicit deny targets only this SID; everyone else retains the allow-all baseline.
        // Removing an approval must remove its exception from EVERY deny rule.
        var exe = new XElement("RuleCollection", new XAttribute("Type", "Exe"),
            new XAttribute("EnforcementMode", enforce ? "Enabled" : "AuditOnly"),
            PathRule(draft, "other-users", "S-1-1-0", "Allow", "*"),
            PathRule(draft, "selected-user", draft.UserSid, "Deny", "*",
                BasePaths.Concat(draft.AllowProgramFiles ? new[] { @"%PROGRAMFILES%\*" } : Array.Empty<string>()).Select(x => new XElement("FilePathCondition", new XAttribute("Path", x))).Concat(hashes)));
        foreach (string path in RestrictedWindowsPaths)
            exe.Add(PathRule(draft, "restricted-" + path, draft.UserSid, "Deny", path, hashes));
        // An EXE collection without packaged-app rules can prevent packaged apps from running.
        var appx = new XElement("RuleCollection", new XAttribute("Type", "Appx"), new XAttribute("EnforcementMode", "Enabled"),
            new XElement("FilePublisherRule", new XAttribute("Id", RuleId(draft.Id, "packaged-apps")),
                new XAttribute("Name", "Sentinella: signed packaged apps"), new XAttribute("Description", "Preserve signed packaged apps"),
                new XAttribute("UserOrGroupSid", "S-1-1-0"), new XAttribute("Action", "Allow"),
                new XElement("Conditions", new XElement("FilePublisherCondition", new XAttribute("PublisherName", "*"),
                    new XAttribute("ProductName", "*"), new XAttribute("BinaryName", "*"),
                    new XElement("BinaryVersionRange", new XAttribute("LowSection", "0.0.0.0"), new XAttribute("HighSection", "*"))))));
        return new XDocument(new XElement("AppLockerPolicy", new XAttribute("Version", "1"), exe, appx)).ToString();
    }
    public static string Fingerprint(string xml)
    {
        using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        var root = XDocument.Load(reader).Root ?? throw new ArgumentException("XML vuoto.");
        string Canonical(XElement e) => "<" + e.Name.LocalName + string.Concat(e.Attributes().OrderBy(a => a.Name.ToString(), StringComparer.Ordinal)
            .Select(a => " " + a.Name + "=\"" + System.Security.SecurityElement.Escape(a.Value) + "\"")) + ">" +
            string.Concat(e.Elements().Where(c => !(c.Name == "RuleCollection" && !c.HasElements &&
                (string?)c.Attribute("EnforcementMode") == "NotConfigured")).Select(Canonical).OrderBy(s => s, StringComparer.Ordinal)) + "</" + e.Name.LocalName + ">";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Canonical(root))));
    }
    public static ApprovedApplication ReadWindowsHash(string path, string name, string rawHash, long length, string nativeXml)
    {
        using var reader = XmlReader.Create(new StringReader(nativeXml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        var xml = XDocument.Load(reader);
        var hashes = xml.Descendants("FileHash").ToArray();
        if (hashes.Length != 1 || (string?)hashes[0].Attribute("Type") != "SHA256")
            throw new IOException("Windows non ha prodotto un singolo hash AppLocker SHA256.");
        var h = hashes[0];
        var approval = new ApprovedApplication(path, name, rawHash, length, (string?)h.Attribute("Data") ?? "",
            (string?)h.Attribute("SourceFileName") ?? "", (long?)h.Attribute("SourceFileLength") ?? 0, DateTimeOffset.UtcNow);
        Validate(new(Guid.NewGuid(), "S-1-5-21-1-2-3-1001", [approval]));
        return approval;
    }
    public static void Save(string path, AppControlDraft draft)
    {
        Validate(draft); Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllText(temp, JsonSerializer.Serialize(draft, new JsonSerializerOptions { WriteIndented = true })); File.Move(temp, path, true); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public static AppControlDraft Load(string path, string userSid)
    {
        if (!File.Exists(path)) return new(Guid.NewGuid(), userSid, []);
        if (new FileInfo(path).Length > 1024 * 1024) throw new IOException("Bozza oltre il limite.");
        var draft = JsonSerializer.Deserialize<AppControlDraft>(File.ReadAllText(path)) ?? throw new IOException("Bozza vuota.");
        Validate(draft);
        if (draft.UserSid != userSid) throw new IOException("La bozza appartiene a un altro utente Windows.");
        return draft;
    }
}
