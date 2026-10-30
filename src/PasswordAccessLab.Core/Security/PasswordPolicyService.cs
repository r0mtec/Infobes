using System.Text;
using PasswordAccessLab.Core.Models;

namespace PasswordAccessLab.Core.Security;

public static class PasswordPolicyService
{
    public static void Validate(string password, UserAccount user)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(user);
        if (password.EnumerateRunes().Count() < user.MinimumPasswordLength)
            throw new ArgumentException($"Минимальная длина пароля: {user.MinimumPasswordLength} символов.");
        if (!user.PasswordRestrictionsEnabled) return;

        bool latin = false, cyrillic = false, arithmetic = false;
        foreach (Rune rune in password.EnumerateRunes())
        {
            int c = rune.Value;
            latin |= c is >= 'A' and <= 'Z' or >= 'a' and <= 'z';
            cyrillic |= c is >= 0x0400 and <= 0x052F or >= 0x1C80 and <= 0x1C8F
                or >= 0x2DE0 and <= 0x2DFF or >= 0xA640 and <= 0xA69F
                or >= 0x1E030 and <= 0x1E08F;
            arithmetic |= c is '+' or '-' or '*' or '/';
        }
        var missing = new List<string>();
        if (!latin) missing.Add("латинскую букву A–Z или a–z");
        if (!cyrillic) missing.Add("символ кириллицы");
        if (!arithmetic) missing.Add("арифметический знак +, -, * или /");
        if (missing.Count != 0)
            throw new ArgumentException("Пароль должен содержать: " + string.Join(", ", missing) + ".");
    }

    public static bool IsExpired(UserAccount user, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (!user.PasswordInitialized || user.PasswordLifetimeMonths == 0) return false;
        if (user.PasswordLifetimeMonths < 0 || user.PasswordChangedAtUtc is null)
            throw new ArgumentException("Некорректные параметры срока действия пароля.");

        // AddMonths учитывает календарные месяцы: например, месяц от 31 января
        // заканчивается в последний день февраля, а не через фиксированные 30 дней.
        // Большой положительный срок, выходящий за DateTimeOffset.MaxValue,
        // не может истечь ни в один из представимых моментов времени.
        DateTimeOffset changed = user.PasswordChangedAtUtc.Value.ToUniversalTime();
        int remainingMonths = (9999 - changed.Year) * 12 + 12 - changed.Month;
        if (user.PasswordLifetimeMonths > remainingMonths) return false;
        return now.ToUniversalTime() >= changed.AddMonths(user.PasswordLifetimeMonths);
    }
}
