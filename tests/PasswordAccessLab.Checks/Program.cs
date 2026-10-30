using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PasswordAccessLab.Core.Models;
using PasswordAccessLab.Core.Security;
using PasswordAccessLab.Core.Services;
using PasswordAccessLab.Core.Storage;

// Автономные проверки без тестового фреймворка и NuGet. Каждый тест получает
// отдельное хранилище в памяти либо новый каталог TEMP; реальная база не открывается.
var checks = new (string Name, Action Run)[]
{
    ("Создание единственного ADMIN с начальными параметрами", CheckInitialDatabase),
    ("Первый вход ADMIN требует установки пароля", CheckInitialAdminLogin),
    ("Незавершённая установка не даёт полномочий", CheckPendingAccess),
    ("Установка пароля сохраняет хеш, дату и флаг", CheckInitialPassword),
    ("Вход ADMIN после установки пароля", CheckAdminLogin),
    ("Три неверных пароля между разными именами", CheckThreeAttempts),
    ("Неизвестное имя не сбрасывает счётчик", CheckUnknownUser),
    ("Успешный вход сбрасывает счётчик", CheckSuccessfulLoginReset),
    ("Новый пользователь получает стандартные параметры", CheckAddUser),
    ("Пустое имя и дубликаты запрещены", CheckDuplicateUsers),
    ("Первый вход обычного пользователя", CheckInitialUserLogin),
    ("Смена пароля проверяет старый пароль и подтверждение", CheckPasswordChange),
    ("Отказ от смены оставляет данные без изменений", CheckCancelledChange),
    ("Пустой установленный пароль не требует повторной инициализации", CheckEmptyPassword),
    ("Блокировка и разблокировка запрещают и разрешают вход", CheckBlocking),
    ("ADMIN не может заблокировать себя", CheckAdminSelfBlock),
    ("Вариант 2 проверяет каждую категорию", CheckPasswordCategories),
    ("Минимальная длина действует без ограничений", CheckMinimumLength),
    ("Смена политики не меняет действующий пароль", CheckDeferredPolicy),
    ("Срок пароля считается календарными месяцами", CheckCalendarLifetime),
    ("Истёкший пароль блокирует доступ до смены", CheckExpiredSession),
    ("Обычный пользователь не вызывает управление напрямую", CheckOrdinaryAccess),
    ("Повторный неуспешный вход снимает прежние полномочия", CheckSessionReset),
    ("Ошибка записи не изменяет учётные записи в памяти", CheckSaveRollback),
    ("MD5 вычисляется от UTF-8 и проверяет пароль", CheckHash),
    ("Одинаковая фраза даёт совместимый ключ и новый IV", CheckCipherRoundTrip),
    ("Формат без метки, старые файлы и повреждение заголовка", CheckCipherFormat),
    ("Все настройки сохраняются после повторного открытия", CheckPersistence),
    ("Неудачное открытие не перезаписывает базу", CheckWrongPhrasePreservesFile),
    ("Отсутствующий ADMIN и повреждённая структура отклоняются", CheckInvalidDatabase),
    ("Create не перезаписывает существующий файл", CheckCreateNoOverwrite),
    ("Save не создаёт заново исчезнувший файл", CheckDeletedFile),
    ("После сохранения нет временных и открытых данных", CheckEncryptedFilesOnly),
};

var failed = 0;
foreach (var check in checks)
{
    try
    {
        check.Run();
        Console.WriteLine($"PASS  {check.Name}");
    }
    catch (Exception ex)
    {
        failed++;
        // Сами пароли, фразы и сериализованная база не выводятся даже при ошибке.
        Console.Error.WriteLine($"FAIL  {check.Name}: {ex.GetType().Name}");
        Console.Error.WriteLine(ex.StackTrace);
    }
}
Console.WriteLine($"Результат: {checks.Length - failed}/{checks.Length} проверок успешно.");
return failed == 0 ? 0 : 1;

static void CheckInitialDatabase()
{
    var database = UserManagementService.CreateInitialDatabase();
    Equal(1, database.SchemaVersion);
    Equal(1, database.Users.Count);
    var admin = database.Users.Single();
    Equal("ADMIN", admin.Username);
    True(admin.IsAdministrator);
    Equal(PasswordHashService.ComputeHash(""), admin.PasswordHash);
    False(admin.IsBlocked);
    False(admin.PasswordInitialized);
    False(admin.PasswordRestrictionsEnabled);
    Equal(0, admin.MinimumPasswordLength);
    Equal(0, admin.PasswordLifetimeMonths);
    True(admin.PasswordChangedAtUtc is null);
}

static void CheckInitialAdminLogin()
{
    var f = new ServiceFixture();
    Equal(LoginResult.RequiresInitialPassword, f.Authentication.Login("admin", ""));
    False(f.Accounts.IsAuthenticated);
    Equal("ADMIN", f.Accounts.CurrentUser!.Username);
    Equal(0, f.Authentication.FailedPasswordAttempts);
}

static void CheckPendingAccess()
{
    var f = new ServiceFixture();
    f.Authentication.Login("ADMIN", "");
    Throws<UnauthorizedAccessException>(() => f.Accounts.GetUsers());
    Throws<UnauthorizedAccessException>(() => f.Accounts.AddUser("other"));
    Throws<UnauthorizedAccessException>(() => f.Accounts.UpdateUserSettings("ADMIN", false, true, 5, 1));
}

static void CheckInitialPassword()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    var user = f.Accounts.CurrentUser!;
    True(f.Accounts.IsAuthenticated);
    True(user.PasswordInitialized);
    Equal(f.Clock.GetUtcNow(), user.PasswordChangedAtUtc!.Value);
    True(PasswordHashService.Verify(ServiceFixture.AdminPassword, user.PasswordHash));
    Equal(user.PasswordHash, f.Repository.Database.Users.Single().PasswordHash);
    Equal(1, f.Repository.SaveCount);
}

static void CheckAdminLogin()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Authentication.Logout();
    Equal(LoginResult.Success, f.Authentication.Login("AdMiN", ServiceFixture.AdminPassword));
    True(f.Accounts.IsAuthenticated);
    Equal(1, f.Accounts.GetUsers().Count);
}

static void CheckThreeAttempts()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Accounts.AddUser("employee");
    f.Authentication.Logout();
    Equal(LoginResult.InvalidPassword, f.Authentication.Login("ADMIN", "wrong"));
    Equal(LoginResult.InvalidPassword, f.Authentication.Login("employee", "wrong"));
    Equal(LoginResult.AttemptsExhausted, f.Authentication.Login("ADMIN", "wrong"));
    Equal(3, f.Authentication.FailedPasswordAttempts);
    True(f.Authentication.MustExit);
    Equal(LoginResult.AttemptsExhausted, f.Authentication.Login("ADMIN", ServiceFixture.AdminPassword));
    False(f.Accounts.IsAuthenticated);
}

static void CheckUnknownUser()
{
    var f = new ServiceFixture();
    Equal(LoginResult.InvalidPassword, f.Authentication.Login("ADMIN", "wrong"));
    Equal(LoginResult.UserNotFound, f.Authentication.Login("absent", ""));
    Equal(1, f.Authentication.FailedPasswordAttempts);
    False(f.Accounts.IsAuthenticated);
    True(f.Accounts.CurrentUser is null);
}

static void CheckSuccessfulLoginReset()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Authentication.Logout();
    f.Authentication.Login("ADMIN", "wrong");
    f.Authentication.Login("ADMIN", "wrong");
    Equal(LoginResult.Success, f.Authentication.Login("ADMIN", ServiceFixture.AdminPassword));
    Equal(0, f.Authentication.FailedPasswordAttempts);
    False(f.Authentication.MustExit);
}

static void CheckAddUser()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Accounts.AddUser("  employee  ");
    var user = f.Accounts.GetUsers().Single(u => !u.IsAdministrator);
    Equal("employee", user.Username);
    False(user.IsBlocked);
    False(user.PasswordInitialized);
    False(user.PasswordRestrictionsEnabled);
    Equal(0, user.MinimumPasswordLength);
    Equal(0, user.PasswordLifetimeMonths);
    True(user.PasswordChangedAtUtc is null);
    True(PasswordHashService.Verify("", user.PasswordHash));
}

static void CheckDuplicateUsers()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Accounts.AddUser("employee");
    Throws<ArgumentException>(() => f.Accounts.AddUser("EMPLOYEE"));
    Throws<ArgumentException>(() => f.Accounts.AddUser("admin"));
    Throws<ArgumentException>(() => f.Accounts.AddUser("   "));
    Equal(2, f.Accounts.GetUsers().Count);
}

static void CheckInitialUserLogin()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Accounts.AddUser("employee");
    f.Authentication.Logout();
    Equal(LoginResult.RequiresInitialPassword, f.Authentication.Login("employee", ""));
    False(f.Accounts.IsAuthenticated);
    f.Authentication.ChangePassword("", "TestПароль+", "TestПароль+");
    True(f.Accounts.IsAuthenticated);
    False(f.Accounts.CurrentUser!.IsAdministrator);
}

static void CheckPasswordChange()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    var previous = f.Accounts.CurrentUser!;
    Throws<ArgumentException>(() => f.Authentication.ChangePassword("wrong", "NewПароль+", "NewПароль+"));
    Throws<ArgumentException>(() => f.Authentication.ChangePassword(ServiceFixture.AdminPassword, "NewПароль+", "different"));
    Equal(previous, f.Accounts.CurrentUser!);
    f.Clock.Advance(TimeSpan.FromDays(2));
    f.Authentication.ChangePassword(ServiceFixture.AdminPassword, "NewПароль+", "NewПароль+");
    Equal(f.Clock.GetUtcNow(), f.Accounts.CurrentUser!.PasswordChangedAtUtc!.Value);
    f.Authentication.Logout();
    Equal(LoginResult.InvalidPassword, f.Authentication.Login("ADMIN", ServiceFixture.AdminPassword));
    Equal(LoginResult.Success, f.Authentication.Login("ADMIN", "NewПароль+"));
}

static void CheckCancelledChange()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    var before = f.Accounts.CurrentUser!;
    var saves = f.Repository.SaveCount;
    // Диалог при «Отмена» не вызывает ChangePassword. Это проверяет отсутствие
    // неявного изменения данных между открытием/чтением профиля и выходом.
    _ = f.Accounts.CurrentUser;
    f.Authentication.Logout();
    Equal(saves, f.Repository.SaveCount);
    Equal(LoginResult.Success, f.Authentication.Login("ADMIN", ServiceFixture.AdminPassword));
    Equal(before, f.Accounts.CurrentUser!);
}

static void CheckEmptyPassword()
{
    var f = new ServiceFixture();
    Equal(LoginResult.RequiresInitialPassword, f.Authentication.Login("ADMIN", ""));
    f.Authentication.ChangePassword("", "", "");
    True(f.Accounts.CurrentUser!.PasswordInitialized);
    f.Authentication.Logout();
    Equal(LoginResult.Success, f.Authentication.Login("ADMIN", ""));
}

static void CheckBlocking()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Accounts.AddUser("employee");
    f.Accounts.UpdateUserSettings("employee", true, false, 0, 0);
    f.Authentication.Logout();
    Equal(LoginResult.Blocked, f.Authentication.Login("employee", ""));
    Equal(LoginResult.Blocked, f.Authentication.Login("employee", "wrong"));
    False(f.Accounts.IsAuthenticated);
    f.Authentication.Login("ADMIN", ServiceFixture.AdminPassword);
    f.Accounts.UpdateUserSettings("employee", false, false, 0, 0);
    f.Authentication.Logout();
    Equal(LoginResult.RequiresInitialPassword, f.Authentication.Login("employee", ""));
}

static void CheckAdminSelfBlock()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    Throws<ArgumentException>(() => f.Accounts.UpdateUserSettings("admin", true, false, 0, 0));
    False(f.Accounts.GetUsers().Single().IsBlocked);
}

static void CheckPasswordCategories()
{
    var user = new UserAccount { Username = "policy", PasswordRestrictionsEnabled = true };
    PasswordPolicyService.Validate("TestПароль+", user);
    PasswordPolicyService.Validate("Aё-💡", user);
    PasswordPolicyService.Validate("AЖ*", user);
    PasswordPolicyService.Validate("Zя/", user);
    Throws<ArgumentException>(() => PasswordPolicyService.Validate("Test123+", user));
    Throws<ArgumentException>(() => PasswordPolicyService.Validate("Пароль123+", user));
    Throws<ArgumentException>(() => PasswordPolicyService.Validate("TestПароль123", user));
    Throws<ArgumentException>(() => PasswordPolicyService.Validate("", user));
    PasswordPolicyService.Validate("", user with { PasswordRestrictionsEnabled = false });
}

static void CheckMinimumLength()
{
    var user = new UserAccount { Username = "policy", MinimumPasswordLength = 4 };
    Throws<ArgumentException>(() => PasswordPolicyService.Validate("abc", user));
    PasswordPolicyService.Validate("abcd", user);
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Accounts.AddUser("employee");
    f.Accounts.UpdateUserSettings("employee", false, false, 4, 0);
    f.Authentication.Logout();
    f.Authentication.Login("employee", "");
    Throws<ArgumentException>(() => f.Authentication.ChangePassword("", "abc", "abc"));
    False(f.Accounts.IsAuthenticated);
    f.Authentication.ChangePassword("", "abcd", "abcd");
    True(f.Accounts.IsAuthenticated);
}

static void CheckDeferredPolicy()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Authentication.ChangePassword(ServiceFixture.AdminPassword, "simple", "simple");
    f.Accounts.UpdateUserSettings("ADMIN", false, true, 12, 0);
    f.Authentication.Logout();
    Equal(LoginResult.Success, f.Authentication.Login("ADMIN", "simple"));
    Throws<ArgumentException>(() => f.Authentication.ChangePassword("simple", "simple2", "simple2"));
    f.Authentication.ChangePassword("simple", "TestПароль123+", "TestПароль123+");
}

static void CheckCalendarLifetime()
{
    var at = new DateTimeOffset(2024, 1, 31, 10, 0, 0, TimeSpan.Zero);
    var user = new UserAccount { Username = "calendar", PasswordInitialized = true, PasswordChangedAtUtc = at, PasswordLifetimeMonths = 1 };
    False(PasswordPolicyService.IsExpired(user, new DateTimeOffset(2024, 2, 29, 9, 59, 59, TimeSpan.Zero)));
    True(PasswordPolicyService.IsExpired(user, new DateTimeOffset(2024, 2, 29, 10, 0, 0, TimeSpan.Zero)));
    False(PasswordPolicyService.IsExpired(user with { PasswordLifetimeMonths = 0 }, at.AddYears(2)));
    False(PasswordPolicyService.IsExpired(user with { PasswordLifetimeMonths = int.MaxValue }, at.AddYears(2)));
}

static void CheckExpiredSession()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Accounts.UpdateUserSettings("ADMIN", false, false, 0, 1);
    f.Authentication.Logout();
    f.Clock.Advance(TimeSpan.FromDays(40));
    Equal(LoginResult.RequiresPasswordChange, f.Authentication.Login("ADMIN", ServiceFixture.AdminPassword));
    False(f.Accounts.IsAuthenticated);
    Throws<UnauthorizedAccessException>(() => f.Accounts.GetUsers());
    Throws<ArgumentException>(() => f.Authentication.ChangePassword("wrong", "NewПароль+", "NewПароль+"));
    False(f.Accounts.IsAuthenticated);
    f.Authentication.ChangePassword(ServiceFixture.AdminPassword, "NewПароль+", "NewПароль+");
    True(f.Accounts.IsAuthenticated);
    Equal(f.Clock.GetUtcNow(), f.Accounts.CurrentUser!.PasswordChangedAtUtc!.Value);
}

static void CheckOrdinaryAccess()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    f.Accounts.AddUser("employee");
    f.Authentication.Logout();
    f.Authentication.Login("employee", "");
    f.Authentication.ChangePassword("", "user", "user");
    Throws<UnauthorizedAccessException>(() => f.Accounts.GetUsers());
    Throws<UnauthorizedAccessException>(() => f.Accounts.AddUser("another"));
    Throws<UnauthorizedAccessException>(() => f.Accounts.UpdateUserSettings("ADMIN", false, false, 0, 0));
}

static void CheckSessionReset()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    Equal(LoginResult.UserNotFound, f.Authentication.Login("absent", ""));
    False(f.Accounts.IsAuthenticated);
    Throws<UnauthorizedAccessException>(() => f.Accounts.AddUser("unexpected"));
}

static void CheckSaveRollback()
{
    var f = new ServiceFixture();
    f.InitializeAdmin();
    var before = f.Accounts.CurrentUser!;
    f.Repository.FailWrites = true;
    Throws<IOException>(() => f.Accounts.AddUser("unsaved"));
    Equal(1, f.Accounts.GetUsers().Count);
    Throws<IOException>(() => f.Accounts.UpdateUserSettings("ADMIN", false, true, 8, 1));
    Equal(before, f.Accounts.CurrentUser!);
    Throws<IOException>(() => f.Authentication.ChangePassword(ServiceFixture.AdminPassword, "NewПароль+", "NewПароль+"));
    Equal(before, f.Accounts.CurrentUser!);
    f.Repository.FailWrites = false;
    f.Authentication.Logout();
    Equal(LoginResult.Success, f.Authentication.Login("ADMIN", ServiceFixture.AdminPassword));
}

static void CheckHash()
{
    Equal("D41D8CD98F00B204E9800998ECF8427E", PasswordHashService.ComputeHash(""));
    Equal("900150983CD24FB0D6963F7D28E17F72", PasswordHashService.ComputeHash("abc"));
    var text = "TestПароль+ё💡";
    Equal(Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(text))), PasswordHashService.ComputeHash(text));
    True(PasswordHashService.Verify(text, PasswordHashService.ComputeHash(text)));
    False(PasswordHashService.Verify(text + "x", PasswordHashService.ComputeHash(text)));
}

static void CheckCipherRoundTrip()
{
    var plaintext = Encoding.UTF8.GetBytes("Данные для проверки DES-CBC");
    using var first = new DesEncryptionService(StorageFixture.Passphrase);
    using var second = new DesEncryptionService(StorageFixture.Passphrase);
    var encrypted = first.Encrypt(plaintext);
    var encryptedAgain = second.Encrypt(plaintext);
    False(encrypted.SequenceEqual(encryptedAgain));
    True(second.Decrypt(encrypted).SequenceEqual(plaintext));
    True(first.Decrypt(encryptedAgain).SequenceEqual(plaintext));
    True(second.Decrypt(first.Encrypt(ReadOnlySpan<byte>.Empty)).Length == 0);
}

static void CheckCipherFormat()
{
    using var right = new DesEncryptionService(StorageFixture.Passphrase);
    var plaintext = Encoding.UTF8.GetBytes("Проверочные данные");
    var original = right.Encrypt(plaintext);
    Equal(2, BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(8, 4)));
    int length = BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(20, 4));
    Equal(DesEncryptionService.HeaderLength + length, original.Length);
    // Сигнатура, версия и длина проверяются независимо от расшифрования.
    foreach (var index in new[] { 0, 8, 20 })
    {
        var changed = original.ToArray();
        changed[index] ^= 0x01;
        ThrowsAny(() => right.Decrypt(changed));
    }
    ThrowsAny(() => right.Decrypt(original.AsSpan(0, original.Length - 1)));

    // Старый формат имеет тот же ключ и шифротекст, но содержит хвост в 32 байта.
    var legacy = new byte[original.Length + DesEncryptionService.LegacyTrailerLength];
    original.CopyTo(legacy, 0);
    BinaryPrimitives.WriteInt32LittleEndian(legacy.AsSpan(8, 4), 1);
    True(right.Decrypt(legacy).SequenceEqual(plaintext));
    var rewritten = right.Encrypt(right.Decrypt(legacy));
    Equal(original.Length, rewritten.Length);
    Equal(2, BinaryPrimitives.ReadInt32LittleEndian(rewritten.AsSpan(8, 4)));

    // Без метки целостности изменение IV меняет первый блок и не вызывает ошибку DES.
    var changedIv = original.ToArray();
    changedIv[12] ^= 1;
    var expected = plaintext.ToArray();
    expected[0] ^= 1;
    True(right.Decrypt(changedIv).SequenceEqual(expected));
}

static void CheckPersistence()
{
    using var file = new StorageFixture();
    using (var repository = file.Open())
    {
        var data = UserManagementService.CreateInitialDatabase();
        repository.Create(data);
        var accounts = new UserManagementService(repository, data);
        var auth = new AuthenticationService(accounts);
        auth.Login("ADMIN", "");
        auth.ChangePassword("", ServiceFixture.AdminPassword, ServiceFixture.AdminPassword);
        accounts.AddUser("employee");
        accounts.UpdateUserSettings("employee", true, true, 9, 2);
        accounts.Save();
    }
    using var reopened = file.Open();
    var loaded = reopened.Load();
    Equal(2, loaded.Users.Count);
    var user = loaded.Users.Single(u => u.Username == "employee");
    True(user.IsBlocked);
    True(user.PasswordRestrictionsEnabled);
    Equal(9, user.MinimumPasswordLength);
    Equal(2, user.PasswordLifetimeMonths);
    var newAccounts = new UserManagementService(reopened, loaded);
    var newAuth = new AuthenticationService(newAccounts);
    Equal(LoginResult.Success, newAuth.Login("ADMIN", ServiceFixture.AdminPassword));
    Equal(LoginResult.Blocked, newAuth.Login("employee", ""));
}

static void CheckWrongPhrasePreservesFile()
{
    using var file = new StorageFixture();
    using (var repository = file.Open()) repository.Create(UserManagementService.CreateInitialDatabase());
    var original = File.ReadAllBytes(file.Path);
    using (var wrong = new EncryptedUserRepository(file.Path, "Неверная проверочная фраза"))
    {
        ThrowsAny(() => wrong.Load());
        ThrowsAny(() => wrong.Save(UserManagementService.CreateInitialDatabase()));
    }
    True(original.SequenceEqual(File.ReadAllBytes(file.Path)));
    var changed = original.ToArray();
    changed[changed.Length / 2] ^= 1;
    File.WriteAllBytes(file.Path, changed);
    using var damaged = file.Open();
    ThrowsAny(() => damaged.Load());
    ThrowsAny(() => damaged.Save(UserManagementService.CreateInitialDatabase()));
    True(changed.SequenceEqual(File.ReadAllBytes(file.Path)));
}

static void CheckInvalidDatabase()
{
    var admin = UserManagementService.CreateInitialDatabase().Users.Single();
    var cases = new[]
    {
        new UserDatabase(),
        new UserDatabase { Users = new() { admin with { IsBlocked = true } } },
        new UserDatabase { Users = new() { admin, admin with { Username = "admin" } } },
        new UserDatabase { Users = new() { admin with { PasswordHash = "broken" } } },
        new UserDatabase { Users = new() { admin with { MinimumPasswordLength = -1 } } },
        new UserDatabase { Users = new() { admin with { PasswordLifetimeMonths = -1 } } },
        new UserDatabase { Users = new() { admin with { PasswordInitialized = true, PasswordChangedAtUtc = null } } },
        new UserDatabase { SchemaVersion = 99, Users = new() { admin } },
    };
    foreach (var data in cases)
    {
        using var file = new StorageFixture();
        // Имитируем файл с корректным шифрованием, но некорректной структурой:
        // это отдельно проверяет проверку ADMIN после расшифрования.
        using var cipher = new DesEncryptionService(StorageFixture.Passphrase);
        File.WriteAllBytes(file.Path, cipher.Encrypt(JsonSerializer.SerializeToUtf8Bytes(data)));
        using var repository = file.Open();
        var bytes = File.ReadAllBytes(file.Path);
        ThrowsAny(() => repository.Load());
        True(bytes.SequenceEqual(File.ReadAllBytes(file.Path)));
    }
}

static void CheckCreateNoOverwrite()
{
    using var file = new StorageFixture();
    using (var repository = file.Open()) repository.Create(UserManagementService.CreateInitialDatabase());
    var bytes = File.ReadAllBytes(file.Path);
    using var second = file.Open();
    ThrowsAny(() => second.Create(UserManagementService.CreateInitialDatabase()));
    True(bytes.SequenceEqual(File.ReadAllBytes(file.Path)));
}

static void CheckDeletedFile()
{
    using var file = new StorageFixture();
    using var repository = file.Open();
    var data = UserManagementService.CreateInitialDatabase();
    repository.Create(data);
    File.Delete(file.Path);
    ThrowsAny(() => repository.Save(data));
    False(File.Exists(file.Path));
    Equal(0, Directory.GetFiles(file.DirectoryPath).Length);
}

static void CheckEncryptedFilesOnly()
{
    using var file = new StorageFixture();
    using var repository = file.Open();
    var data = UserManagementService.CreateInitialDatabase();
    repository.Create(data);
    data.Users.Add(new UserAccount { Username = "UniqueVisibleAccountName" });
    repository.Save(data);
    repository.Save(data);
    var paths = Directory.GetFiles(file.DirectoryPath);
    Equal(1, paths.Length);
    Equal(file.Path, paths.Single());
    var bytes = File.ReadAllBytes(file.Path);
    var visible = Encoding.UTF8.GetString(bytes);
    False(visible.Contains("UniqueVisibleAccountName", StringComparison.Ordinal));
    False(visible.Contains("PasswordHash", StringComparison.Ordinal));
    False(visible.Contains(StorageFixture.Passphrase, StringComparison.Ordinal));
    True(repository.Load().Users.Count == 2);
}

static void True(bool value)
{
    if (!value) throw new CheckFailedException();
}

static void False(bool value) => True(!value);

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new CheckFailedException();
}

static void Throws<T>(Action action) where T : Exception
{
    try { action(); }
    catch (T) { return; }
    throw new CheckFailedException();
}

static void ThrowsAny(Action action)
{
    try { action(); }
    catch (Exception ex) when (ex is not CheckFailedException) { return; }
    throw new CheckFailedException();
}

sealed class CheckFailedException : Exception;

sealed class FrozenTimeProvider : TimeProvider
{
    private DateTimeOffset _now = new(2026, 1, 15, 12, 30, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => _now;
    public void Advance(TimeSpan duration) => _now += duration;
}

sealed class MemoryRepository(UserDatabase database) : IUserRepository
{
    public UserDatabase Database { get; private set; } = Clone(database);
    public bool FailWrites { get; set; }
    public int SaveCount { get; private set; }
    public UserDatabase Load() => Clone(Database);
    public void Save(UserDatabase data)
    {
        if (FailWrites) throw new IOException("Проверочная ошибка записи.");
        Database = Clone(data);
        SaveCount++;
    }
    private static UserDatabase Clone(UserDatabase data) => new()
    {
        SchemaVersion = data.SchemaVersion,
        Users = data.Users.Select(u => u with { }).ToList()
    };
}

sealed class ServiceFixture
{
    public const string AdminPassword = "AdminПароль+";
    public FrozenTimeProvider Clock { get; } = new();
    public MemoryRepository Repository { get; }
    public UserManagementService Accounts { get; }
    public AuthenticationService Authentication { get; }
    public ServiceFixture()
    {
        var database = UserManagementService.CreateInitialDatabase();
        Repository = new MemoryRepository(database);
        Accounts = new UserManagementService(Repository, database, Clock);
        Authentication = new AuthenticationService(Accounts, Clock);
    }
    public void InitializeAdmin()
    {
        Authentication.Login("ADMIN", "");
        Authentication.ChangePassword("", AdminPassword, AdminPassword);
    }
}

sealed class StorageFixture : IDisposable
{
    public const string Passphrase = "Проверочная фраза варианта 2";
    public string DirectoryPath { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "PasswordAccessLab.Checks", Guid.NewGuid().ToString("N"));
    public string Path => System.IO.Path.Combine(DirectoryPath, "users.dat");
    public StorageFixture() => Directory.CreateDirectory(DirectoryPath);
    public EncryptedUserRepository Open() => new(Path, Passphrase);
    public void Dispose()
    {
        // Каталог выбран и создан самим тестом; внутри только тестовый шифротекст.
        if (Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, recursive: true);
    }
}
