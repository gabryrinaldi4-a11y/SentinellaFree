using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace Sentinella.Core;
public sealed record ReleaseManifest(string Version, string FileName, long Size, string Sha256, string Url, DateTimeOffset Expires);
public static class ReleaseVerification
{
    public static ReleaseManifest Verify(byte[] json, byte[] signature, string pinnedPublicKeyPem, Version current, DateTimeOffset now)
    {
        if (json.Length is 0 or > 16384 || signature.Length is 0 or > 2048 || string.IsNullOrWhiteSpace(pinnedPublicKeyPem)) throw new InvalidDataException("Manifesto o chiave di rilascio non validi.");
        using var rsa = RSA.Create(); rsa.ImportFromPem(pinnedPublicKeyPem);
        if (rsa.KeySize < 3072 || !rsa.VerifyData(json, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) throw new CryptographicException("Firma del manifesto non valida.");
        var value = JsonSerializer.Deserialize<ReleaseManifest>(json) ?? throw new InvalidDataException("Manifesto vuoto.");
        if (!Regex.IsMatch(value.Version ?? "", @"^\d{1,4}\.\d{1,4}\.\d{1,4}$") || !Version.TryParse(value.Version, out var version) || version <= current)
            throw new InvalidDataException("Versione non piu recente: aggiornamento o replay rifiutato.");
        if (!Regex.IsMatch(value.FileName ?? "", @"^[A-Za-z0-9][A-Za-z0-9._-]{1,180}\.zip$") || !Regex.IsMatch(value.Sha256 ?? "", @"^[A-Fa-f0-9]{64}$") || value.Size is <= 0 or > 1024L * 1024 * 1024)
            throw new InvalidDataException("File di aggiornamento non valido.");
        if (value.Expires <= now || value.Expires > now.AddDays(45)) throw new InvalidDataException("Manifesto scaduto o con validita eccessiva.");
        string expected = "https://github.com/gabryrinaldi4-a11y/SentinellaFree/releases/download/v" + value.Version + "/" + value.FileName;
        if (!string.Equals(value.Url, expected, StringComparison.Ordinal)) throw new InvalidDataException("Origine di aggiornamento non autorizzata.");
        return value;
    }
    public static async Task VerifyArchiveAsync(string path, ReleaseManifest manifest, CancellationToken token = default)
    {
        await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, true);
        if (file.Length != manifest.Size || !Convert.ToHexString(await SHA256.HashDataAsync(file, token)).Equals(manifest.Sha256, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("Integrita del pacchetto di aggiornamento non valida.");
    }
}
public static class InstallationIntegrity
{
    sealed record Component(string Name, string SHA256);
    public static string Check(string root)
    {
        string path = Path.Combine(root, "original-components.json");
        if (!File.Exists(path)) return "Manifesto componenti assente: integrita non verificata.";
        if (new FileInfo(path).Length > 65536) throw new IOException("Manifesto componenti oltre il limite.");
        var components = JsonSerializer.Deserialize<List<Component>>(File.ReadAllText(path)) ?? throw new IOException("Manifesto vuoto.");
        string[] expected = ["SentinellaFree.exe", "SentinellaFree.dll", "Sentinella.Core.dll"];
        if (components.Count != expected.Length || !components.Select(c => c.Name).Order().SequenceEqual(expected.Order())) throw new IOException("Manifesto componenti inatteso.");
        foreach (var component in components)
        {
            using var input = File.OpenRead(Path.Combine(root, component.Name));
            if (!Convert.ToHexString(SHA256.HashData(input)).Equals(component.SHA256, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("Componente cambiato: " + component.Name);
        }
        return "Hash dei componenti coerenti con il manifesto locale. Non prova l'identita dell'editore e non impedisce la manomissione da parte dello stesso utente.";
    }
}
