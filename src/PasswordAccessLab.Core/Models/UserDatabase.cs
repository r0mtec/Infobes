using System.Text.Json.Serialization;

namespace PasswordAccessLab.Core.Models;

public sealed class UserDatabase
{
    [JsonRequired]
    public int SchemaVersion { get; init; } = 1;
    [JsonRequired]
    public List<UserAccount> Users { get; init; } = new();
}
