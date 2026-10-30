using PasswordAccessLab.Core.Models;
using PasswordAccessLab.Core.Services;

namespace PasswordAccessLab.WinForms.Forms;

internal sealed class UserSettingsForm : StyledForm
{
    private readonly ComboBox _users = new() { DropDownStyle = ComboBoxStyle.DropDownList, DisplayMember = "Username", Margin = new Padding(0, 0, 0, 18) };
    private readonly CheckBox _blocked = new() { Text = "Учетная запись заблокирована", AutoSize = true, Margin = new Padding(0, 0, 0, 14) };
    private readonly CheckBox _restrictions = new() { Text = "Требовать латиницу, кириллицу и знак + - * /", AutoSize = true, Margin = new Padding(0, 0, 0, 20) };
    private readonly NumericUpDown _minimum = Number();
    private readonly NumericUpDown _lifetime = Number();

    public UserSettingsForm(UserManagementService accounts, string? selectedUsername = null, string? field = null)
        : base("Параметры пользователя", new Size(660, 630))
    {
        var content = Ui.Content(this);
        Ui.Row(content, Ui.Label("Параметры доступа", true));
        Ui.Row(content, Ui.Label("Ограничения состава и длины применяются при следующей смене пароля. Срок действия проверяется при следующем входе."));
        Ui.Field(content, "Пользователь", _users);
        Ui.Row(content, _blocked);
        Ui.Row(content, _restrictions);
        Ui.Field(content, "Минимальная длина пароля · 0 — без ограничения", _minimum);
        Ui.Field(content, "Срок действия в месяцах · 0 — бессрочно", _lifetime);
        Ui.Row(content, Ui.Label("Администратора ADMIN нельзя заблокировать."));
        _users.SelectedIndexChanged += (_, _) => LoadSelection();
        _users.Items.AddRange(accounts.GetUsers().Cast<object>().ToArray());
        _users.SelectedIndex = 0;
        if (selectedUsername is not null)
            _users.SelectedItem = _users.Items.Cast<UserAccount>().FirstOrDefault(u => string.Equals(u.Username, selectedUsername, StringComparison.OrdinalIgnoreCase)) ?? _users.Items[0];
        var save = Ui.Button("Сохранить", (_, _) =>
        {
            if (_users.SelectedItem is not UserAccount selected) return;
            if (_blocked.Checked && !selected.IsBlocked && !Ui.Confirm(this, $"Заблокировать пользователя «{selected.Username}»? Вход станет недоступен.")) return;
            if (Ui.Attempt(this, () => accounts.UpdateUserSettings(selected.Username, _blocked.Checked,
                _restrictions.Checked, (int)_minimum.Value, (int)_lifetime.Value))) DialogResult = DialogResult.OK;
        }, true);
        var cancel = Ui.Button("Отмена");
        cancel.DialogResult = DialogResult.Cancel;
        Ui.Actions(content, save, cancel);
        AcceptButton = save;
        CancelButton = cancel;
        Shown += (_, _) =>
        {
            Control target = field switch { "block" => _blocked, "restrictions" => _restrictions, "minimum" => _minimum, "lifetime" => _lifetime, _ => _users };
            target.Focus();
        };
    }

    private static NumericUpDown Number() => new()
    {
        Minimum = 0, Maximum = int.MaxValue, DecimalPlaces = 0,
        ThousandsSeparator = true, Margin = new Padding(0, 0, 0, 18)
    };

    private void LoadSelection()
    {
        if (_users.SelectedItem is not UserAccount user) return;
        _blocked.Checked = user.IsBlocked;
        _blocked.Enabled = !user.IsAdministrator;
        _restrictions.Checked = user.PasswordRestrictionsEnabled;
        _minimum.Value = user.MinimumPasswordLength;
        _lifetime.Value = user.PasswordLifetimeMonths;
    }
}
