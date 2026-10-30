using PasswordAccessLab.Core.Services;
using PasswordAccessLab.Core.Models;

namespace PasswordAccessLab.WinForms.Forms;

internal sealed class ChangePasswordForm : StyledForm
{
    private readonly TextBox _old = Ui.Input(true);
    private readonly TextBox _new = Ui.Input(true);
    private readonly TextBox _confirmation = Ui.Input(true);

    public ChangePasswordForm(AuthenticationService authentication, UserAccount user, bool initial = false, bool mandatory = false)
        : base(initial ? "Первоначальная установка пароля" : "Смена пароля", new Size(610, initial ? 515 : 590))
    {
        var content = Ui.Content(this);
        Ui.Row(content, Ui.Label(initial ? "Установите пароль" : "Смените пароль", true));
        string policy = $"Учетная запись: {user.Username}. Минимальная длина: {user.MinimumPasswordLength}. " +
            (user.PasswordRestrictionsEnabled ? "Нужны латинская буква, кириллица и один из знаков + - * /." : "Ограничения состава выключены.");
        Ui.Row(content, Ui.Label(policy));
        if (!initial) Ui.Field(content, "Старый пароль", _old);
        Ui.Field(content, "Новый пароль", _new);
        Ui.Field(content, "Подтверждение нового пароля", _confirmation);
        if (mandatory) Ui.Row(content, Ui.Label("Продолжить работу можно только после установки пароля. Отмена завершит программу."));
        var save = Ui.Button("Сохранить", (_, _) =>
        {
            try
            {
                authentication.ChangePassword(initial ? string.Empty : _old.Text, _new.Text, _confirmation.Text);
                DialogResult = DialogResult.OK;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException or IOException or InvalidDataException or System.Security.Cryptography.CryptographicException)
            {
                Ui.Error(this, ex);
            }
        }, true);
        var cancel = Ui.Button(mandatory ? "Выход" : "Отмена");
        cancel.DialogResult = DialogResult.Cancel;
        Ui.Actions(content, save, cancel);
        AcceptButton = save;
        CancelButton = cancel;
        Shown += (_, _) => { if (initial) _new.Focus(); else _old.Focus(); };
        FormClosed += (_, _) => { _old.Clear(); _new.Clear(); _confirmation.Clear(); };
    }
}
