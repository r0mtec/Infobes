using System.Security.Cryptography;
using System.Text;

namespace PasswordAccessLab.Core.Security;

public static class PasswordHashService
{
    public static string ComputeHash(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        // В хранилище попадает
        // только шестнадцатеричное представление 16-байтного результата.
        byte[] utf8 = Encoding.UTF8.GetBytes(password);
        byte[]? hash = null;
        try
        {
            hash = MD5.HashData(utf8);
            return Convert.ToHexString(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
            if (hash is not null) CryptographicOperations.ZeroMemory(hash);
        }
    }

    public static bool Verify(string password, string storedHash)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (storedHash is null || storedHash.Length != 32) return false;
        byte[] expected;
        try { expected = Convert.FromHexString(storedHash); }
        catch (FormatException) { return false; }
        byte[] utf8 = Encoding.UTF8.GetBytes(password);
        byte[]? actual = null;
        try
        {
            actual = MD5.HashData(utf8);
            // Сравниваем байты, а не строки; время сравнения не зависит
            // от позиции первого несовпадающего байта хеша.
            return CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
            CryptographicOperations.ZeroMemory(expected);
            if (actual is not null) CryptographicOperations.ZeroMemory(actual);
        }
    }
}
