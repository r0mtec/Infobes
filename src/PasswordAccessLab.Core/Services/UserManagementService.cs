using PasswordAccessLab.Core.Models;
using PasswordAccessLab.Core.Security;
using PasswordAccessLab.Core.Storage;

namespace PasswordAccessLab.Core.Services;

public sealed class UserManagementService
{
    private readonly IUserRepository _repository;
    private readonly TimeProvider _timeProvider;
    private List<UserAccount> _users;
    private string? _sessionUsername;
    private bool _sessionComplete;

    public UserManagementService(IUserRepository repository, UserDatabase data,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(repository);
        ArgumentNullException.ThrowIfNull(data);
        _repository = repository;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _users = data.Users.Select(user => user with { }).ToList();
    }


    public UserAccount? CurrentUser => _sessionUsername is null ? null : FindUser(_sessionUsername);

    public bool IsAuthenticated => _sessionComplete && CurrentUser is { IsBlocked: false };

    internal TimeProvider Clock => _timeProvider;

    public static UserDatabase CreateInitialDatabase()
    {
        // У ADMIN нет установленного пароля. Хеш пустой строки позволяет проверить
        // первый вход, а отдельный флаг принуждает пройти диалог установки пароля.
        return new UserDatabase
        {
            SchemaVersion = 1,
            Users = [CreateUser("ADMIN")]
        };
    }

    public IReadOnlyList<UserAccount> GetUsers()
    {
        EnsureAdministrator();
        return _users.OrderByDescending(user => user.IsAdministrator)
            .ThenBy(user => user.Username, StringComparer.OrdinalIgnoreCase)
            .Select(user => user with { }).ToList().AsReadOnly();
    }

    public UserAccount AddUser(string username)
    {
        EnsureAdministrator();
        string normalized = ValidateUsername(username);
        if (FindUser(normalized) is not null)
            throw new ArgumentException("Пользователь с таким именем уже существует.");

        UserAccount added = CreateUser(normalized);
        List<UserAccount> updated = [.. _users, added];
        Persist(updated);
        return added;
    }

    public UserAccount UpdateUserSettings(string username, bool blocked, bool restrictions,
        int minimumLength, int lifetimeMonths)
    {
        EnsureAdministrator();
        UserAccount user = FindUser(username?.Trim() ?? "")
            ?? throw new ArgumentException("Пользователь не найден.");
        if (minimumLength < 0)
            throw new ArgumentException("Минимальная длина пароля не может быть отрицательной.");
        if (lifetimeMonths < 0)
            throw new ArgumentException("Срок действия пароля не может быть отрицательным.");
        if (user.IsAdministrator && blocked)
            throw new ArgumentException("Нельзя заблокировать учётную запись ADMIN.");

        // Изменение политики не проверяет старый пароль: новые требования начинают
        // действовать при следующей установке/смене; срок проверяется при следующем входе.
        UserAccount updatedUser = user with
        {
            IsBlocked = blocked,
            PasswordRestrictionsEnabled = restrictions,
            MinimumPasswordLength = minimumLength,
            PasswordLifetimeMonths = lifetimeMonths
        };
        ReplaceAndPersist(updatedUser);
        return updatedUser;
    }


    public void Save() => _repository.Save(Snapshot(_users));

    internal UserAccount? FindUser(string username) => _users.FirstOrDefault(user =>
        string.Equals(user.Username, username, StringComparison.OrdinalIgnoreCase));

    internal void BeginSession(UserAccount user, bool complete)
    {
        _sessionUsername = user.Username;
        _sessionComplete = complete;
    }

    internal void ClearSession()
    {
        _sessionUsername = null;
        _sessionComplete = false;
    }

    internal void ChangeCurrentPassword(string password, DateTimeOffset changedAtUtc)
    {
        UserAccount user = CurrentUser
            ?? throw new UnauthorizedAccessException("Сначала выполните вход в программу.");
        if (user.IsBlocked)
            throw new UnauthorizedAccessException("Учётная запись заблокирована.");

        UserAccount updated = user with
        {
            PasswordHash = PasswordHashService.ComputeHash(password),
            PasswordChangedAtUtc = changedAtUtc.ToUniversalTime(),
            PasswordInitialized = true
        };
        ReplaceAndPersist(updated);
        // Полноценный доступ появляется лишь после успешной записи нового пароля.
        _sessionComplete = true;
    }

    private void EnsureAdministrator()
    {
        // Скрытия меню недостаточно: прямой вызов бизнес-метода тоже обязан
        // проверять завершённую сессию, блокировку и реальную роль текущего пользователя.
        if (!IsAuthenticated || CurrentUser is not { IsAdministrator: true })
            throw new UnauthorizedAccessException("Для этой операции требуются права администратора.");
    }

    private void ReplaceAndPersist(UserAccount replacement)
    {
        List<UserAccount> updated = _users.Select(user =>
            string.Equals(user.Username, replacement.Username, StringComparison.OrdinalIgnoreCase)
                ? replacement : user).ToList();
        Persist(updated);
    }

    private void Persist(List<UserAccount> updated)
    {
        // Сначала атомарно сохраняется зашифрованный снимок. При ошибке записи
        // действующий список в памяти остаётся прежним, поэтому интерфейс может повторить операцию.
        _repository.Save(Snapshot(updated));
        _users = updated;
    }

    private static UserDatabase Snapshot(IEnumerable<UserAccount> users) => new()
    {
        SchemaVersion = 1,
        Users = users.Select(user => user with { }).ToList()
    };

    private static string ValidateUsername(string username)
    {
        string normalized = username?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(normalized))
            throw new ArgumentException("Введите имя пользователя.");
        if (normalized.Length > 128)
            throw new ArgumentException("Имя пользователя должно содержать не более 128 символов.");
        if (normalized.Any(char.IsControl))
            throw new ArgumentException("Имя пользователя не должно содержать управляющие символы.");
        return normalized;
    }

    private static UserAccount CreateUser(string username) => new()
    {
        Username = username,
        PasswordHash = PasswordHashService.ComputeHash(""),
        IsBlocked = false,
        PasswordRestrictionsEnabled = false,
        MinimumPasswordLength = 0,
        PasswordLifetimeMonths = 0,
        PasswordChangedAtUtc = null,
        PasswordInitialized = false
    };
}
