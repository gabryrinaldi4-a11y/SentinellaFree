using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sentinella.Core;

/// <summary>
/// Manual account-bound quarantine. Original bytes are removed only after an authenticated
/// encrypted copy has been committed and read back. Restore copies to a new explicit path;
/// the encrypted copy is retained. This is not a security boundary against the same user/admin.
/// </summary>
public sealed class QuarantineStore
{
    public const long MaxContentBytes = 32L * 1024 * 1024;
    private const long MaxEnvelopeBytes = 80L * 1024 * 1024;
    private readonly string directory;
    private readonly SemaphoreSlim gate = new(1, 1);
    private record Payload(QuarantineEntry Entry, byte[] Content);
    private record Envelope(int Format, string Id, byte[] ProtectedKey, byte[] Nonce, byte[] Tag, byte[] Ciphertext);

    public QuarantineStore(string directory)
    {
        this.directory = NativeFiles.NormalizeLocal(directory);
        NativeFiles.RejectReparseAncestors(this.directory);
        Directory.CreateDirectory(this.directory);
        NativeFiles.RejectReparseAncestors(this.directory);
    }

    private string ItemPath(string id)
    {
        if (!Guid.TryParseExact(id, "N", out _)) throw new InvalidDataException("ID quarantena non valido.");
        return Path.Combine(directory, id + ".sqf");
    }

    public IReadOnlyList<QuarantineEntry> List()
    {
        gate.Wait();
        try
        {
            NativeFiles.RejectReparseAncestors(directory);
            var entries = new List<QuarantineEntry>();
            foreach (var path in Directory.EnumerateFiles(directory, "*.sqf"))
            {
                if (entries.Count >= 10000) throw new IOException("Troppe voci in quarantena.");
                var payload = Read(Path.GetFileNameWithoutExtension(path));
                entries.Add(payload.Entry);
                CryptographicOperations.ZeroMemory(payload.Content);
            }
            return entries.OrderByDescending(e => e.CreatedAt).ToList();
        }
        finally { gate.Release(); }
    }

    public async Task<QuarantineEntry> QuarantineAsync(Finding finding)
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try { return await Task.Run(() => Quarantine(finding)).ConfigureAwait(false); }
        finally { gate.Release(); }
    }

    private QuarantineEntry Quarantine(Finding finding)
    {
        if (finding.Verdict != "LocalHashMatch")
            throw new InvalidOperationException("Quarantena ammessa solo per una corrispondenza hash locale esplicita.");
        if (finding.Sha256.Length != 64 || !finding.Sha256.All(Uri.IsHexDigit))
            throw new InvalidDataException("Hash atteso non valido.");
        string source = NativeFiles.NormalizeLocal(finding.Path);
        if (source.StartsWith(directory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase)) throw new IOException("La quarantena non può contenere sé stessa.");
        NativeFiles.RejectReparseAncestors(directory);
        using var input = NativeFiles.OpenStable(source, true, true);
        if (input.Length > MaxContentBytes) throw new IOException("Quarantena limitata a 32 MiB per file.");
        var bytes = new byte[checked((int)input.Length)];
        input.ReadExactly(bytes);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[]? plaintext = null;
        string id = Guid.NewGuid().ToString("N");
        string temporary = Path.Combine(directory, id + ".tmp");
        string final = ItemPath(id);
        try
        {
            string actualHash = Convert.ToHexString(SHA256.HashData(bytes));
            if (!string.Equals(actualHash, finding.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Il file è cambiato dopo la scansione: originale conservato.");
            var entry = new QuarantineEntry(id, source, actualHash, finding.Detail, DateTimeOffset.UtcNow);
            plaintext = JsonSerializer.SerializeToUtf8Bytes(new Payload(entry, bytes));
            byte[] nonce = RandomNumberGenerator.GetBytes(12), tag = new byte[16], cipher = new byte[plaintext.Length];
            using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plaintext, cipher, tag, Aad(id));
            var envelope = new Envelope(1, id, UserProtection.Protect(key), nonce, tag, cipher);
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write,
                FileShare.None, 65536, FileOptions.WriteThrough))
            {
                NativeFiles.AssertHandlePath(output.SafeFileHandle, temporary);
                JsonSerializer.Serialize(output, envelope);
                output.Flush(true);
            }
            NativeFiles.RejectReparseAncestors(directory);
            File.Move(temporary, final, false);
            var verified = Read(id);
            bool verifiedHash = verified.Entry.Sha256 == actualHash &&
                CryptographicOperations.FixedTimeEquals(SHA256.HashData(verified.Content), SHA256.HashData(bytes));
            CryptographicOperations.ZeroMemory(verified.Content);
            if (!verifiedHash) throw new CryptographicException("Verifica copia cifrata non riuscita; originale conservato.");
            NativeFiles.DeleteOnClose(input);
            return entry;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(key);
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public async Task RestoreAsync(string id, string destination)
    {
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            await Task.Run(() =>
            {
                string target = NativeFiles.NormalizeLocal(destination);
                if (target.StartsWith(directory.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar,
                    StringComparison.OrdinalIgnoreCase)) throw new IOException("Ripristina fuori dalla quarantena.");
                NativeFiles.RejectReparseAncestors(target);
                var payload = Read(id);
                try
                {
                    using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write,
                        FileShare.None, 65536, FileOptions.WriteThrough);
                    NativeFiles.AssertHandlePath(output.SafeFileHandle, target);
                    output.Write(payload.Content);
                    output.Flush(true);
                }
                finally { CryptographicOperations.ZeroMemory(payload.Content); }
            }).ConfigureAwait(false);
        }
        finally { gate.Release(); }
    }

    private Payload Read(string id)
    {
        string path = ItemPath(id);
        NativeFiles.RejectReparseAncestors(directory);
        using var stream = NativeFiles.OpenStable(path, false, true);
        if (stream.Length > MaxEnvelopeBytes) throw new InvalidDataException("File quarantena oltre il limite.");
        var envelope = JsonSerializer.Deserialize<Envelope>(stream) ?? throw new InvalidDataException("Quarantena vuota.");
        if (envelope.Format != 1 || envelope.Id != id || envelope.ProtectedKey is null ||
            envelope.ProtectedKey.Length > 65536 || envelope.Nonce?.Length != 12 || envelope.Tag?.Length != 16 ||
            envelope.Ciphertext is null || envelope.Ciphertext.Length > MaxContentBytes * 2)
            throw new InvalidDataException("Formato quarantena non valido.");
        byte[] key = UserProtection.Unprotect(envelope.ProtectedKey);
        byte[] plaintext = new byte[envelope.Ciphertext.Length];
        try
        {
            if (key.Length != 32) throw new CryptographicException("Chiave quarantena non valida.");
            using (var aes = new AesGcm(key, 16))
                aes.Decrypt(envelope.Nonce, envelope.Ciphertext, envelope.Tag, plaintext, Aad(id));
            var payload = JsonSerializer.Deserialize<Payload>(plaintext) ?? throw new InvalidDataException("Payload vuoto.");
            if (payload.Entry is null || payload.Content is null || payload.Content.Length > MaxContentBytes ||
                payload.Entry.Id != id || payload.Entry.Sha256 != Convert.ToHexString(SHA256.HashData(payload.Content)))
                throw new CryptographicException("Integrità della quarantena non valida.");
            return payload;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
    private static byte[] Aad(string id) => Encoding.UTF8.GetBytes("SentinellaQuarantine:1:" + id);
}
