using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace PasswordAccessLab.Core.Security;

public sealed class DesEncryptionService : IDisposable
{
    public const int HeaderLength = 24;
    public const int LegacyTrailerLength = 32;
    public const int MaximumPlaintextLength = 16 * 1024 * 1024;
    private const int KeyIterations = 200_000;
    private static ReadOnlySpan<byte> Magic => "PALABV02"u8;
    private readonly byte[] _desKey;
    private bool _disposed;

    public DesEncryptionService(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        byte[] phraseBytes = Encoding.UTF8.GetBytes(passphrase);
        byte[]? material = null;
        try
        {
            material = Rfc2898DeriveBytes.Pbkdf2(phraseBytes,
                "PasswordAccessLab/Variant2/KeyMaterial/v1"u8,
                KeyIterations, HashAlgorithmName.SHA256, 40);
            _desKey = DeriveNonWeakDesKey(material);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(phraseBytes);
            if (material is not null) CryptographicOperations.ZeroMemory(material);
        }
    }

    private static byte[] DeriveNonWeakDesKey(ReadOnlySpan<byte> material)
    {
        byte[] candidate = material[..8].ToArray();
        Span<byte> counterBytes = stackalloc byte[4];
        // .NET запрещает слабые и полуслабые DES-ключи. Если такой ключ получен,
        // повторяем детерминированное получение с возрастающим счетчиком.
        // Никакого RNG и случайной добавки к ключу здесь нет; повторный запуск
        // с той же фразой пройдет ровно ту же последовательность кандидатов.
        for (int counter = 1; DES.IsWeakKey(candidate) || DES.IsSemiWeakKey(candidate); counter++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(counterBytes, counter);
            byte[] next = HMACSHA256.HashData(material, counterBytes);
            CryptographicOperations.ZeroMemory(candidate);
            candidate = next.AsSpan(0, 8).ToArray();
            CryptographicOperations.ZeroMemory(next);
        }
        return candidate;
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (plaintext.Length > MaximumPlaintextLength)
            throw new ArgumentException("Размер базы пользователей превышает допустимый предел.");
        using DES des = CreateDes();
        // Для каждого шифрования создается независимый случайный IV размером
        // с блок DES (8 байт). Он записывается открыто в заголовок и не меняет ключ.
        byte[] iv = RandomNumberGenerator.GetBytes(8);
        byte[] ciphertext = des.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);
        var file = new byte[HeaderLength + ciphertext.Length];
        Magic.CopyTo(file);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(8, 4), 2);
        iv.CopyTo(file, 12);
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(20, 4), ciphertext.Length);
        ciphertext.CopyTo(file, HeaderLength);
        return file;
    }

    public byte[] Decrypt(ReadOnlySpan<byte> file)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (file.Length < HeaderLength + 8 || !file[..8].SequenceEqual(Magic))
            throw InvalidFile();
        int version = BinaryPrimitives.ReadInt32LittleEndian(file.Slice(8, 4));
        int trailerLength = 0;
        int cipherLength = BinaryPrimitives.ReadInt32LittleEndian(file.Slice(20, 4));
        if (cipherLength < 8 || cipherLength % 8 != 0
            || cipherLength > MaximumPlaintextLength + 8
            || file.Length != HeaderLength + cipherLength + trailerLength)
            throw InvalidFile();

        // Расшифровываем в память. Репозиторий затем проверяет JSON и ADMIN.
        // Эти проверки не гарантируют обнаружения всех изменений шифротекста.
        using DES des = CreateDes();
        return des.DecryptCbc(file.Slice(HeaderLength, cipherLength), file.Slice(12, 8), PaddingMode.PKCS7);
    }

    private DES CreateDes()
    {
        DES des = DES.Create();
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.PKCS7;
        des.Key = _desKey;
        return des;
    }

    private static CryptographicException InvalidFile() =>
        new("Неверная парольная фраза или поврежденный файл учетных записей.");

    public void Dispose()
    {
        if (_disposed) return;
        CryptographicOperations.ZeroMemory(_desKey);
        _disposed = true;
    }
}
