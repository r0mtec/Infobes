namespace PasswordAccessLab.Core.Services;

public enum LoginResult
{
    Success,
    UserNotFound,
    InvalidPassword,
    Blocked,
    RequiresInitialPassword,
    RequiresPasswordChange,
    AttemptsExhausted
}
