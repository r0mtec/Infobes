using System.Security.Cryptography;
using System.Text;
using PasswordAccessLab.Core.Models;
using PasswordAccessLab.Core.Services;
using PasswordAccessLab.Core.Storage;
using PasswordAccessLab.WinForms.Forms;

namespace PasswordAccessLab.WinForms;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        try
        {
            string path = ResolveDataPath(args);
            // Один экземпляр на путь хранилища в текущем сеансе Windows.
            // Репозиторий дополнительно обнаруживает внешние изменения файла.
            string pathId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path.ToUpperInvariant())));
            using var mutex = new Mutex(true, @"Local\PasswordAccessLab." + pathId, out bool firstInstance);
            if (!firstInstance)
            {
                MessageBox.Show("Это хранилище уже открыто в другом экземпляре программы.", AppInfo.Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try { Run(path); }
            finally { mutex.ReleaseMutex(); }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or InvalidOperationException or CryptographicException or System.Text.Json.JsonException)
        {
            MessageBox.Show("Не удалось открыть хранилище. Проверьте парольную фразу, целостность файла и права доступа.\n\n" + ex.Message,
                "Ошибка запуска", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static string ResolveDataPath(string[] args)
    {
        if (args.Length == 0) return EncryptedUserRepository.DefaultFilePath;
        if (args.Length == 2 && args[0] == "--data-file" && !string.IsNullOrWhiteSpace(args[1]))
            return Path.GetFullPath(args[1]);
        throw new ArgumentException("Допустимый аргумент запуска: --data-file <путь к users.dat>.");
    }

    private static void Run(string path)
    {
        bool firstLaunch = !File.Exists(path);
        using var phraseForm = new PassphraseForm(firstLaunch);
        if (phraseForm.ShowDialog() != DialogResult.OK) return;
        using var repository = new EncryptedUserRepository(path, phraseForm.Passphrase);
        phraseForm.ClearSecrets();

        UserDatabase database;
        if (firstLaunch)
        {
            // Создание происходит исключительно при отсутствии файла. Create
            // не перезапишет файл, появившийся после проверки первого запуска.
            database = UserManagementService.CreateInitialDatabase();
            repository.Create(database);
        }
        else database = repository.Load(); // Ошибка ведет к выходу, а не к новой базе.

        var accounts = new UserManagementService(repository, database);
        var authentication = new AuthenticationService(accounts);
        using var login = new LoginForm(authentication, accounts);
        if (login.ShowDialog() == DialogResult.OK && accounts.IsAuthenticated)
        {
            using var main = new MainForm(accounts, authentication);
            Application.Run(main);
        }
        else accounts.Save();
        authentication.Logout();
    }
}
