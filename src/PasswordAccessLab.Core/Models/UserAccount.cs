using System.Text.Json.Serialization;

namespace PasswordAccessLab.Core.Models;

/// <summary>Снимок учетной записи; изменение выполняется заменой записи через сервис.</summary>
public sealed record UserAccount
{
    [JsonRequired]
    public string Username { get; init; } = string.Empty;
    [JsonRequired]
    public string PasswordHash { get; init; } = "D41D8CD98F00B204E9800998ECF8427E";
    [JsonRequired]
    public bool IsBlocked { get; init; }
    [JsonRequired]
    public bool PasswordRestrictionsEnabled { get; init; }
    [JsonRequired]
    public int MinimumPasswordLength { get; init; }
    [JsonRequired]
    public int PasswordLifetimeMonths { get; init; }
    [JsonRequired]
    public DateTimeOffset? PasswordChangedAtUtc { get; init; }
    [JsonRequired]
    public bool PasswordInitialized { get; init; }

    [JsonIgnore]
    public bool IsAdministrator => string.Equals(Username, "ADMIN", StringComparison.OrdinalIgnoreCase);
}
