using PasswordAccessLab.Core.Services;

namespace PasswordAccessLab.WinForms.Forms;

internal sealed class LoginForm : StyledForm
{
    private readonly TextBox _username = Ui.Input();
    private readonly TextBox _password = Ui.Input(true);
    private readonly AuthenticationService _authentication;
    private readonly UserManagementService _accounts;

    public LoginForm(AuthenticationService authentication, UserManagementService accounts)
        : base("Вход в систему", new Size(555, 425))
    {
        _authentication = authentication;
        _accounts = accounts;
        var content = Ui.Content(this);
        Ui.Row(content, Ui.Label("Вход в систему", true));
        Ui.Row(content, Ui.Label("Введите данные своей учетной записи."));
        Ui.Field(content, "Имя пользователя", _username);
        Ui.Field(content, "Пароль", _password);
        var enter = Ui.Button("Войти", (_, _) => Login(), true);
        var exit = Ui.Button("Выход");
        exit.DialogResult = DialogResult.Cancel;
        Ui.Actions(content, enter, exit);
        AcceptButton = enter;
        CancelButton = exit;
        Shown += (_, _) => _username.Focus();
        FormClosed += (_, _) => _password.Clear();
    }

    private void Login()
    {
        var result = _authentication.Login(_username.Text, _password.Text);
        _password.Clear();
        switch (result)
        {
            case LoginResult.Success:
                DialogResult = DialogResult.OK;
                return;
            case LoginResult.RequiresInitialPassword:
            case LoginResult.RequiresPasswordChange:
                if (result == LoginResult.RequiresPasswordChange)
                    MessageBox.Show(this, "Срок действия пароля истек. Чтобы продолжить, смените пароль.", "Смена пароля", MessageBoxButtons.OK, MessageBoxIcon.Information);
                using (var change = new ChangePasswordForm(_authentication, _accounts.CurrentUser!,
                    initial: result == LoginResult.RequiresInitialPassword, mandatory: true))
                {
                    DialogResult = change.ShowDialog(this) == DialogResult.OK ? DialogResult.OK : DialogResult.Cancel;
                }
                return;
            case LoginResult.AttemptsExhausted:
                MessageBox.Show(this, "Три неверных пароля подряд. Программа будет завершена.", "Вход запрещен", MessageBoxButtons.OK, MessageBoxIcon.Error);
                DialogResult = DialogResult.Cancel;
                return;
            case LoginResult.UserNotFound:
                if (MessageBox.Show(this, "Пользователь не найден. Повторить ввод?", "Вход в систему", MessageBoxButtons.RetryCancel, MessageBoxIcon.Warning) == DialogResult.Cancel)
                    DialogResult = DialogResult.Cancel;
                else { _username.Focus(); _username.SelectAll(); }
                return;
            case LoginResult.Blocked:
                MessageBox.Show(this, "Учетная запись заблокирована. Обратитесь к администратору.", "Вход запрещен", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                break;
            default:
                MessageBox.Show(this, $"Неверный пароль. Осталось попыток: {3 - _authentication.FailedPasswordAttempts}.", "Ошибка входа", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                break;
        }
        _password.Focus();
    }
}
