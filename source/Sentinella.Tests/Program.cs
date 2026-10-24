using System.Security.Cryptography;
using System.Text.Json;
using Sentinella.Core;

int passed = 0, skipped = 0;
string root = Path.Combine(Path.GetTempPath(), "SentinellaTests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
void Assert(bool condition, string message)
{
    if (!condition) throw new Exception(message);
    passed++;
    Console.WriteLine("PASS " + message);
}
async Task Reject(Func<Task> action, string message)
{
    bool rejected = false;
    try { await action(); }
    catch (Exception ex) when (ex is IOException or InvalidDataException or InvalidOperationException or CryptographicException or JsonException or System.ComponentModel.Win32Exception)
    { rejected = true; }
    Assert(rejected, message);
}
try
{
    string file = Path.Combine(root, "benign.txt");
    byte[] fixture = "Sentinella: fixture innocua per test di integrità, nessun malware."u8.ToArray();
    File.WriteAllBytes(file, fixture);
    string hash = Convert.ToHexString(SHA256.HashData(fixture));
    var noRules = new LocalScanner();
    var baseScan = await noRules.ScanAsync(file);
    Assert(noRules.RuleCount == 0 && baseScan.Findings.Single().Verdict == "NoLocalMatch", "No database never reports clean");
    Assert(baseScan.FilesScanned == 1 && baseScan.Findings[0].Sha256 == hash, "Streaming SHA256 matches independent digest");
    string rules = Path.Combine(root, "rules.json");
    File.WriteAllText(rules, JsonSerializer.Serialize(new[] { new { sha256 = hash.ToLowerInvariant(), name = "Fixture innocua di test" } }));
    var scanner = new LocalScanner(rules);
    var scan = await scanner.ScanAsync(file);
    Finding match = scan.Findings.Single();
    Assert(scanner.RuleCount == 1 && match.Verdict == "LocalHashMatch", "Exact local rule detects benign test fixture");
    string wrongRules = Path.Combine(root, "wrong.json");
    File.WriteAllText(wrongRules, "[{\"sha256\":\"BAD\",\"name\":\"test\"}]");
    await Reject(() => Task.Run(() => new LocalScanner(wrongRules)), "Malformed SHA256 rejected");
    File.WriteAllText(wrongRules, "{}");
    await Reject(() => Task.Run(() => new LocalScanner(wrongRules)), "Wrong JSON root rejected");
    File.WriteAllText(wrongRules, JsonSerializer.Serialize(new[] { new { sha256 = hash, name = "a" }, new { sha256 = hash, name = "b" } }));
    await Reject(() => Task.Run(() => new LocalScanner(wrongRules)), "Duplicate hash rejected");
    var missing = await scanner.ScanAsync(Path.Combine(root, "absent"));
    Assert(missing.FilesScanned == 0 && missing.Errors.Count > 0, "Missing target reported as error");
    using (var cts = new CancellationTokenSource())
    {
        cts.Cancel();
        bool cancelled = false;
        try { await scanner.ScanAsync(file, cts.Token); }
        catch (OperationCanceledException) { cancelled = true; }
        Assert(cancelled, "Cancellation honored");
    }
    string storeDirectory = Path.Combine(root, "quarantine");
    var store = new QuarantineStore(storeDirectory);
    await Reject(() => store.QuarantineAsync(baseScan.Findings.Single()), "Unmatched file cannot be quarantined");
    File.AppendAllText(file, " changed");
    await Reject(() => store.QuarantineAsync(match), "Changed file cannot be quarantined");
    Assert(File.Exists(file) && store.List().Count == 0, "Changed source preserved and no quarantine committed");
    File.WriteAllBytes(file, fixture);
    var entry = await store.QuarantineAsync(match);
    Assert(!File.Exists(file) && store.List().Single().Sha256 == hash, "Authenticated quarantine commits before removing source");
    string encrypted = Directory.GetFiles(storeDirectory, "*.sqf").Single();
    Assert(!File.ReadAllText(encrypted).Contains("fixture innocua"), "Stored envelope contains no plaintext fixture");
    string restored = Path.Combine(root, "restored.txt");
    await store.RestoreAsync(entry.Id, restored);
    Assert(File.ReadAllBytes(restored).SequenceEqual(fixture), "DPAPI plus AES-GCM roundtrip restores exact bytes");
    Assert(store.List().Count == 1, "Restore retains encrypted recovery copy");
    await Reject(() => store.RestoreAsync(entry.Id, restored), "Restore refuses overwriting existing file");
    await Reject(() => store.RestoreAsync("../escape", Path.Combine(root, "escape.txt")), "Quarantine ID path traversal rejected");
    string savedEnvelope = File.ReadAllText(encrypted);
    using (var document = JsonDocument.Parse(savedEnvelope))
    {
        var element = document.RootElement;
        byte[] cipher = element.GetProperty("Ciphertext").GetBytesFromBase64();
        cipher[0] ^= 1;
        var changed = new
        {
            Format = element.GetProperty("Format").GetInt32(),
            Id = element.GetProperty("Id").GetString(),
            ProtectedKey = element.GetProperty("ProtectedKey").GetBytesFromBase64(),
            Nonce = element.GetProperty("Nonce").GetBytesFromBase64(),
            Tag = element.GetProperty("Tag").GetBytesFromBase64(),
            Ciphertext = cipher
        };
        File.WriteAllText(encrypted, JsonSerializer.Serialize(changed));
    }
    string tamperTarget = Path.Combine(root, "tamper-output.txt");
    await Reject(() => store.RestoreAsync(entry.Id, tamperTarget), "Ciphertext tampering rejected");
    Assert(!File.Exists(tamperTarget), "Authentication failure creates no restored file");
    File.WriteAllText(encrypted, savedEnvelope);
    try
    {
        string external = Path.Combine(root, "external"); Directory.CreateDirectory(external);
        File.WriteAllText(Path.Combine(external, "external.txt"), "innocua");
        string scanDirectory = Path.Combine(root, "scan"); Directory.CreateDirectory(scanDirectory);
        Directory.CreateSymbolicLink(Path.Combine(scanDirectory, "linked"), external);
        var linkScan = await scanner.ScanAsync(scanDirectory);
        Assert(linkScan.FilesScanned == 0 && linkScan.FilesSkipped == 1 && linkScan.Errors.Count > 0,
            "Directory links not traversed");
        await Reject(() => store.RestoreAsync(entry.Id, Path.Combine(scanDirectory, "linked", "restored.txt")),
            "Restore through linked ancestor rejected");
    }
    catch (Exception ex) when (ex is UnauthorizedAccessException || ex is IOException && (ex.HResult & 0xFFFF) == 1314)
    { skipped++; Console.WriteLine("SKIP symlink tests: privilege unavailable"); }
    string hardOriginal = Path.Combine(root, "hard-original.txt");
    string hardAlias = Path.Combine(root, "hard-alias.txt");
    File.WriteAllBytes(hardOriginal, fixture);
    if (!TestNative.CreateHardLinkW(hardAlias, hardOriginal, IntPtr.Zero))
        throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
    await Reject(() => store.QuarantineAsync(new Finding(hardOriginal, hash, "LocalHashMatch", "Fixture")),
        "Hardlinked source cannot be quarantined");
    Assert(File.Exists(hardOriginal) && File.Exists(hardAlias), "Hardlink rejection preserves every source name");
    using (var locked = new FileStream(restored, FileMode.Open, FileAccess.Read, FileShare.None))
    {
        var lockedScan = await scanner.ScanAsync(restored);
        Assert(lockedScan.FilesScanned == 0 && lockedScan.Errors.Count == 1,
            "Locked file reported as scan error");
    }    Console.WriteLine($"RESULT {passed} passed, {skipped} skipped, 0 failed");
    return 0;
}
finally
{
    // Only this test-created, GUID-named temporary directory is deleted.
    if (Directory.Exists(root)) Directory.Delete(root, true);
}


internal static class TestNative
{
    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
    internal static extern bool CreateHardLinkW(string alias, string existing, IntPtr security);
}
