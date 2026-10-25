namespace Sentinella.Core;
public static class BehavioralSignals
{
    public static ProtectionAlert? Process(string executable, string? commandLine, string? parent, DateTimeOffset now)
    {
        string file = Path.GetFileName(executable).ToLowerInvariant(), args = commandLine ?? "", ancestor = Path.GetFileName(parent ?? "").ToLowerInvariant();
        bool shell = file is "powershell.exe" or "pwsh.exe" or "cmd.exe" or "wscript.exe" or "cscript.exe" or "mshta.exe";
        bool office = ancestor is "winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe";
        bool encoded = args.Contains("-encodedcommand", StringComparison.OrdinalIgnoreCase) || args.Contains("-enc ", StringComparison.OrdinalIgnoreCase);
        bool remote = args.Contains("https://", StringComparison.OrdinalIgnoreCase) || args.Contains("http://", StringComparison.OrdinalIgnoreCase);
        if (shell && office || (file is "mshta.exe" or "rundll32.exe") && remote || shell && encoded && remote)
            return new(now, "Warning", "ProcessBehavior", executable, "Combinazione da esaminare: avvio da Office o uso remoto di un interprete. Segnale euristico, non rilevamento confermato; nessun processo terminato. Argomenti non registrati.");
        return null;
    }
}
public sealed class FileBurstDetector
{
    readonly Dictionary<string, DateTimeOffset> files = new(StringComparer.OrdinalIgnoreCase); readonly object sync = new(); DateTimeOffset lastAlert;
    public ProtectionAlert? Observe(string path, DateTimeOffset now)
    {
        lock (sync)
        {
            foreach (string old in files.Where(p => now - p.Value > TimeSpan.FromSeconds(15)).Select(p => p.Key).ToArray()) files.Remove(old);
            if (files.Count < 1000 || files.ContainsKey(path)) files[path] = now;
            if (files.Count < 150 || now - lastAlert < TimeSpan.FromMinutes(2)) return null; lastAlert = now;
            return new(now, "Warning", "FileBurst", Path.GetDirectoryName(path) ?? path, "Molti file diversi modificati in 15 secondi. Puo essere un aggiornamento, una copia o un comportamento sospetto. Non identifica il processo responsabile e non blocca ransomware.");
        }
    }
}
