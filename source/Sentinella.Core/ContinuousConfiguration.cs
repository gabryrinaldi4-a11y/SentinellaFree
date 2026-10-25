using System.Text.Json;
namespace Sentinella.Core;
public static class ContinuousConfiguration
{
    public static void Validate(ContinuousSettings config)
    {
        if (config.Folders is null || config.Folders.Count > 8 || config.Enabled && config.Folders.Count == 0 || config.UpdateHours is < 2 or > 48)
            throw new ArgumentException("Scegli da una a otto cartelle e un intervallo aggiornamenti tra 2 e 48 ore.");
        foreach (string path in config.Folders)
        {
            string full = NativeFiles.NormalizeLocal(path); NativeFiles.RejectReparseAncestors(full);
            if (config.Enabled && !Directory.Exists(full) || full.TrimEnd('\\').Equals(Path.GetPathRoot(full)?.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Scegli cartelle esistenti, non l'intera radice del disco.");
        }
    }
    public static ContinuousSettings Load(string path)
    {
        if (!File.Exists(path)) return new(false, []);
        if (new FileInfo(path).Length > 65536) throw new IOException("Configurazione oltre il limite.");
        var value = JsonSerializer.Deserialize<ContinuousSettings>(File.ReadAllText(path)) ?? throw new IOException("Configurazione vuota."); Validate(value with { Enabled = false }); return value;
    }
    public static void Save(string path, ContinuousSettings config) { Validate(config); AtomicJson.Write(path, config); }
}
public static class AtomicJson
{
    public static void Write<T>(string path, T value)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllText(temp, JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true })); File.Move(temp, path, true); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
public sealed class DebouncedChanges(int maximum = 2000)
{
    readonly Dictionary<string, (DateTimeOffset At, int Attempts)> pending = new(StringComparer.OrdinalIgnoreCase); readonly object sync = new();
    public int Count { get { lock (sync) return pending.Count; } }
    public bool Add(string path, DateTimeOffset now, int attempts = 0)
    {
        lock (sync) { if (!pending.ContainsKey(path) && pending.Count >= maximum) return false; pending[path] = (now, attempts); return true; }
    }
    public (string Path, int Attempts)? Take(DateTimeOffset now)
    {
        lock (sync) { foreach (var pair in pending) if (now - pair.Value.At >= TimeSpan.FromSeconds(2)) { pending.Remove(pair.Key); return (pair.Key, pair.Value.Attempts); } return null; }
    }
}
