using PasswordAccessLab.Core.Models;
using PasswordAccessLab.Core.Security;

namespace PasswordAccessLab.Core.Services;

public sealed class AuthenticationService
{
    private readonly UserManagementService _accounts;
    private readonly TimeProvider _timeProvider;

    public AuthenticationService(UserManagementService accounts, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(accounts);
        _accounts = accounts;
        _timeProvider = timeProvider ?? accounts.Clock;
    }

    public int FailedPasswordAttempts { get; private set; }

    public bool MustExit => FailedPasswordAttempts >= 3;

    public LoginResult Login(string username, string password)
    {
        _accounts.ClearSession();
        if (MustExit)
            return LoginResult.AttemptsExhausted;

        UserAccount? user = _accounts.FindUser(username?.Trim() ?? "");
        if (user is null)
            return LoginResult.UserNotFound;
        if (user.IsBlocked)
            return LoginResult.Blocked;
        if (!PasswordHashService.Verify(password, user.PasswordHash))
        {
            FailedPasswordAttempts++;
            return MustExit ? LoginResult.AttemptsExhausted : LoginResult.InvalidPassword;
        }

        FailedPasswordAttempts = 0;
        if (!user.PasswordInitialized)
        {
            _accounts.BeginSession(user, complete: false);
            return LoginResult.RequiresInitialPassword;
        }

        // IsExpired сравнивает now с датой изменения + N календарных месяцев,
        // поэтому февраль и месяцы разной длины обрабатываются корректно.
        if (PasswordPolicyService.IsExpired(user, _timeProvider.GetUtcNow()))
        {
            _accounts.BeginSession(user, complete: false);
            return LoginResult.RequiresPasswordChange;
        }

        _accounts.BeginSession(user, complete: true);
        return LoginResult.Success;
    }

    public void ChangePassword(string oldPassword, string newPassword, string confirmation)
    {
        if (MustExit)
            throw new UnauthorizedAccessException("Исчерпаны попытки входа. Завершите программу.");

        UserAccount user = _accounts.CurrentUser
            ?? throw new UnauthorizedAccessException("Сначала выполните вход в программу.");
        if (user.IsBlocked)
            throw new UnauthorizedAccessException("Учётная запись заблокирована.");
        if (!PasswordHashService.Verify(oldPassword, user.PasswordHash))
            throw new ArgumentException("Старый пароль введён неверно.");
        if (!string.Equals(newPassword, confirmation, StringComparison.Ordinal))
            throw new ArgumentException("Новый пароль и подтверждение не совпадают.");

        PasswordPolicyService.Validate(newPassword, user);
        _accounts.ChangeCurrentPassword(newPassword, _timeProvider.GetUtcNow());
    }

    public void Logout() => _accounts.ClearSession();
}
