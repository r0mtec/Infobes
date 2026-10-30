using PasswordAccessLab.Core.Services;

namespace PasswordAccessLab.WinForms.Forms;

internal sealed class AddUserForm : StyledForm
{
    public AddUserForm(UserManagementService accounts) : base("Добавить пользователя", new Size(575, 360))
    {
        var content = Ui.Content(this);
        Ui.Row(content, Ui.Label("Новый пользователь", true));
        Ui.Row(content, Ui.Label("Новая учетная запись получит пустой пароль. При первом входе пользователь обязательно установит свой пароль."));
        var username = Ui.Input();
        Ui.Field(content, "Имя пользователя", username);
        var save = Ui.Button("Добавить", (_, _) =>
        {
            if (Ui.Attempt(this, () => accounts.AddUser(username.Text))) DialogResult = DialogResult.OK;
        }, true);
        var cancel = Ui.Button("Отмена");
        cancel.DialogResult = DialogResult.Cancel;
        Ui.Actions(content, save, cancel);
        AcceptButton = save;
        CancelButton = cancel;
        Shown += (_, _) => username.Focus();
    }
}
