using PasswordAccessLab.Core.Services;

namespace PasswordAccessLab.WinForms.Forms;

internal sealed class MainForm : StyledForm
{
    private readonly UserManagementService _accounts;
    private readonly AuthenticationService _authentication;
    private readonly Label _details = Ui.Label("");

    public MainForm(UserManagementService accounts, AuthenticationService authentication)
        : base(AppInfo.Title, new Size(950, 590), true)
    {
        if (!accounts.IsAuthenticated) throw new UnauthorizedAccessException("Необходимо завершить вход в систему.");
        _accounts = accounts;
        _authentication = authentication;
        MinimumSize = new Size(760, 470);
        var menu = new MenuStrip { BackColor = Color.White, Padding = new Padding(16, 8, 8, 8), Font = Font };
        var programMenu = new ToolStripMenuItem("Программа");
        programMenu.DropDownItems.Add("Выход", null, (_, _) => Close());
        menu.Items.Add(programMenu);
        if (accounts.CurrentUser!.IsAdministrator)
        {
            var usersMenu = new ToolStripMenuItem("Пользователи");
            usersMenu.DropDownItems.Add("Список пользователей", null, (_, _) => ShowUsers());
            usersMenu.DropDownItems.Add("Добавить пользователя", null, (_, _) => AddUser());
            usersMenu.DropDownItems.Add(new ToolStripSeparator());
            usersMenu.DropDownItems.Add("Блокировать / разблокировать пользователя", null, (_, _) => Settings("block"));
            usersMenu.DropDownItems.Add("Настроить ограничения пароля", null, (_, _) => Settings("restrictions"));
            usersMenu.DropDownItems.Add("Установить минимальную длину пароля", null, (_, _) => Settings("minimum"));
            usersMenu.DropDownItems.Add("Установить срок действия пароля", null, (_, _) => Settings("lifetime"));
            menu.Items.Add(usersMenu);
        }
        var accountMenu = new ToolStripMenuItem("Учетная запись");
        accountMenu.DropDownItems.Add("Сменить пароль", null, (_, _) => ChangePassword());
        menu.Items.Add(accountMenu);
        var helpMenu = new ToolStripMenuItem("Справка");
        helpMenu.DropDownItems.Add("О программе", null, (_, _) => { using var about = new AboutForm(); about.ShowDialog(this); });
        menu.Items.Add(helpMenu);
        MainMenuStrip = menu;

        var content = Ui.Content(this, 38);
        Ui.Row(content, Ui.Label(accounts.CurrentUser.IsAdministrator ? "Управление доступом" : "Личная учетная запись", true));
        Ui.Row(content, Ui.Label($"Вы вошли как {accounts.CurrentUser.Username}"));
        Ui.Row(content, _details);
        var actions = new FlowLayoutPanel { AutoSize = true, WrapContents = true, Margin = new Padding(0, 12, 0, 24) };
        if (accounts.CurrentUser.IsAdministrator)
        {
            actions.Controls.Add(Ui.Button("Список пользователей", (_, _) => ShowUsers(), true));
            actions.Controls.Add(Ui.Button("Добавить пользователя", (_, _) => AddUser()));
        }
        actions.Controls.Add(Ui.Button("Сменить пароль", (_, _) => ChangePassword(), !accounts.CurrentUser.IsAdministrator));
        Ui.Row(content, actions);
        Ui.Row(content, Ui.Label(accounts.CurrentUser.IsAdministrator
            ? "Управляйте блокировкой и индивидуальными требованиями к паролям через меню «Пользователи». Изменения сохраняются сразу."
            : "Вы можете изменить собственный пароль в меню «Учетная запись». По вопросам доступа обратитесь к администратору."));
        var status = new StatusStrip { BackColor = Color.White, SizingGrip = true };
        status.Items.Add(new ToolStripStatusLabel("Лабораторная работа №1  ·  Вариант №2"));
        Controls.Add(menu);
        Controls.Add(status);
        UpdateDetails();
        FormClosing += (_, e) =>
        {
            // Все операции уже сохранены; контрольная запись при штатном выходе
            // также должна завершиться успешно либо оставить окно открытым.
            if (!Ui.Attempt(this, accounts.Save))
                e.Cancel = !Ui.Confirm(this, "Не удалось выполнить контрольное сохранение. Предыдущие успешные изменения уже записаны. Завершить программу?");
        };
    }

    private void UpdateDetails()
    {
        var user = _accounts.CurrentUser!;
        _details.Text = $"Роль: {(user.IsAdministrator ? "администратор" : "пользователь")}\n\n" +
            $"Пароль изменен: {user.PasswordChangedAtUtc?.ToLocalTime().ToString("dd.MM.yyyy HH:mm")}\n" +
            $"Минимальная длина: {user.MinimumPasswordLength}\n" +
            $"Ограничения состава: {(user.PasswordRestrictionsEnabled ? "латиница, кириллица, + - * /" : "выключены")}\n" +
            $"Срок действия: {(user.PasswordLifetimeMonths == 0 ? "бессрочно" : $"{user.PasswordLifetimeMonths} мес.")}";
    }

    private void ShowUsers() => Ui.Attempt(this, () => { using var form = new UsersForm(_accounts); form.ShowDialog(this); UpdateDetails(); });
    private void AddUser() => Ui.Attempt(this, () => { using var form = new AddUserForm(_accounts); form.ShowDialog(this); });
    private void Settings(string field) => Ui.Attempt(this, () => { using var form = new UserSettingsForm(_accounts, field: field); form.ShowDialog(this); UpdateDetails(); });
    private void ChangePassword()
    {
        using var form = new ChangePasswordForm(_authentication, _accounts.CurrentUser!);
        if (form.ShowDialog(this) == DialogResult.OK)
        {
            UpdateDetails();
            MessageBox.Show(this, "Пароль успешно изменен.", "Учетная запись", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
    }
}
