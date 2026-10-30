using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using PasswordAccessLab.Core.Models;
using PasswordAccessLab.Core.Security;

namespace PasswordAccessLab.Core.Storage;

/// <summary>Единственное место записи базы на диск; пишет только шифротекст.</summary>
public sealed class EncryptedUserRepository : IUserRepository, IDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16
    };
    private readonly DesEncryptionService _encryption;
    private readonly object _sync = new();
    private byte[]? _lastFileHash;
    private bool _ready;
    private bool _disposed;

    public static string DefaultFilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PasswordAccessLab", "users.dat");

    public string FilePath { get; }
    public bool Exists => File.Exists(FilePath);

    public EncryptedUserRepository(string filePath, string passphrase)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        FilePath = Path.GetFullPath(filePath);
        _encryption = new DesEncryptionService(passphrase);
    }

    public UserDatabase Load()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            // При любой ошибке чтения разрешение на Save отзывается: поврежденную
            // или нерасшифрованную базу нельзя заменить новыми учетными записями.
            _ready = false;
            byte[] file = ReadEncryptedFile();
            byte[]? plaintext = null;
            try
            {
                plaintext = _encryption.Decrypt(file);
                UserDatabase data;
                try
                {
                    data = JsonSerializer.Deserialize<UserDatabase>(plaintext, JsonOptions)
                        ?? throw new InvalidDataException("Файл не содержит базу пользователей.");
                }
                catch (JsonException error)
                {
                    throw new InvalidDataException("Неверная парольная фраза или поврежденные данные учетных записей.", error);
                }
                ValidateDatabase(data);
                SetLastFileHash(file);
                _ready = true;
                return data;
            }
            finally
            {
                if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    public void Create(UserDatabase data)
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (File.Exists(FilePath))
                throw new IOException("Файл учетных записей уже существует. Перезапустите программу для его открытия.");
            ValidateDatabase(data);
            byte[] encrypted = SerializeAndEncrypt(data);
            WriteAtomically(encrypted, createNew: true);
            SetLastFileHash(encrypted);
            _ready = true;
        }
    }

    public void Save(UserDatabase data)
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (!_ready || _lastFileHash is null)
                throw new InvalidOperationException("Перед сохранением необходимо успешно открыть или создать базу пользователей.");
            ValidateDatabase(data);
            // Проверяем, что на диске остается именно успешно открытая версия.
            // Удаление/подмена/порча файла во время работы не ведет к перезаписи.
            byte[] currentHash = SHA256.HashData(ReadEncryptedFile());
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(currentHash, _lastFileHash))
                    throw new IOException("Файл учетных записей изменен другим процессом. Сохранение отменено; перезапустите программу.");
            }
            finally { CryptographicOperations.ZeroMemory(currentHash); }
            byte[] encrypted = SerializeAndEncrypt(data);
            WriteAtomically(encrypted, createNew: false);
            SetLastFileHash(encrypted);
        }
    }

    private byte[] SerializeAndEncrypt(UserDatabase data)
    {
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(data, JsonOptions);
        try { return _encryption.Encrypt(plaintext); }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private byte[] ReadEncryptedFile()
    {
        using var stream = new FileStream(FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        const int maxFileSize = DesEncryptionService.MaximumPlaintextLength +
            DesEncryptionService.HeaderLength + DesEncryptionService.LegacyTrailerLength + 8;
        if (stream.Length > maxFileSize)
            throw new InvalidDataException("Размер файла учетных записей превышает допустимый предел.");
        byte[] file = new byte[checked((int)stream.Length)];
        stream.ReadExactly(file);
        return file;
    }

    private void WriteAtomically(byte[] encrypted, bool createNew)
    {
        string directory = Path.GetDirectoryName(FilePath)!;
        Directory.CreateDirectory(directory);
        string temporaryPath = Path.Combine(directory,
            "." + Path.GetFileName(FilePath) + "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            // Временный файл уже содержит готовый зашифрованный контейнер,
            // включая IV. Flush(true) запрашивает сброс буферов на диск.
            using (var stream = new FileStream(temporaryPath, FileMode.CreateNew,
                FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(encrypted);
                stream.Flush(flushToDisk: true);
            }
            if (createNew)
                File.Move(temporaryPath, FilePath, overwrite: false);
            else
                File.Replace(temporaryPath, FilePath, destinationBackupFileName: null);
        }
        finally
        {
            // После неудачи остается старая база; ненужный шифротекст удаляем.
            // Обычное удаление не обещает физического стирания секторов SSD.
            if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
        }
    }

    private static void ValidateDatabase(UserDatabase data)
    {
        ArgumentNullException.ThrowIfNull(data);
        if (data.SchemaVersion != 1 || data.Users is null || data.Users.Count == 0)
            throw new InvalidDataException("Неверная версия или пустая база учетных записей.");
        var usernames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int administrators = 0;
        foreach (UserAccount user in data.Users)
        {
            if (user is null || string.IsNullOrWhiteSpace(user.Username)
                || user.Username.Length > 128 || user.Username != user.Username.Trim()
                || user.Username.Any(char.IsControl) || !usernames.Add(user.Username))
                throw new InvalidDataException("Файл содержит недопустимые или повторяющиеся имена пользователей.");
            if (user.PasswordHash is null || user.PasswordHash.Length != 32
                || user.PasswordHash.Any(c => !Uri.IsHexDigit(c))
                || user.MinimumPasswordLength < 0 || user.PasswordLifetimeMonths < 0)
                throw new InvalidDataException("Файл содержит некорректный хеш или параметры пароля.");
            if (user.PasswordInitialized != user.PasswordChangedAtUtc.HasValue
                || (user.PasswordChangedAtUtc.HasValue && user.PasswordChangedAtUtc.Value.Offset != TimeSpan.Zero)
                || (!user.PasswordInitialized && !PasswordHashService.Verify(string.Empty, user.PasswordHash)))
                throw new InvalidDataException("Файл содержит некорректные параметры первоначальной установки пароля.");
            if (user.IsAdministrator)
            {
                administrators++;
                if (user.IsBlocked)
                    throw new InvalidDataException("Учетная запись ADMIN не может быть заблокирована.");
            }
        }
        if (administrators != 1)
            throw new InvalidDataException("Файл должен содержать ровно одну корректную учетную запись ADMIN.");
    }

    private void SetLastFileHash(byte[] file)
    {
        if (_lastFileHash is not null) CryptographicOperations.ZeroMemory(_lastFileHash);
        _lastFileHash = SHA256.HashData(file);
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed) return;
            _encryption.Dispose();
            if (_lastFileHash is not null) CryptographicOperations.ZeroMemory(_lastFileHash);
            _ready = false;
            _disposed = true;
        }
    }
}
