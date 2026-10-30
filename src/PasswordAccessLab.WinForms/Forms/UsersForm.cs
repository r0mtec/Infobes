using PasswordAccessLab.Core.Services;

namespace PasswordAccessLab.WinForms.Forms;

internal sealed class UsersForm : StyledForm
{
    private readonly UserManagementService _accounts;
    private readonly DataGridView _grid = new()
    {
        Dock = DockStyle.Fill, ReadOnly = true, AutoGenerateColumns = false,
        AllowUserToAddRows = false, AllowUserToDeleteRows = false,
        AllowUserToResizeRows = false, MultiSelect = false, RowHeadersVisible = false,
        SelectionMode = DataGridViewSelectionMode.FullRowSelect,
        BackgroundColor = Color.White, BorderStyle = BorderStyle.None,
        AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
        ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.AutoSize,
        EnableHeadersVisualStyles = false, GridColor = Color.FromArgb(226, 232, 240),
        Margin = new Padding(0, 0, 0, 0)
    };
    private readonly Label _count = Ui.Label("");
    private string? SelectedUsername => _grid.CurrentRow?.Cells[0].Value as string;

    public UsersForm(UserManagementService accounts) : base("Список пользователей", new Size(1150, 660), true)
    {
        _accounts = accounts;
        MinimumSize = new Size(940, 480);
        var content = Ui.Content(this);
        Ui.Row(content, Ui.Label("Пользователи", true));
        Ui.Row(content, _count);
        _grid.ColumnHeadersDefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.FromArgb(232, 238, 248), ForeColor = Ui.Ink, Font = new Font("Segoe UI", 10, FontStyle.Bold), Padding = new Padding(8), WrapMode = DataGridViewTriState.True };
        _grid.DefaultCellStyle = new DataGridViewCellStyle { BackColor = Color.White, ForeColor = Ui.Ink, SelectionBackColor = Color.FromArgb(219, 232, 255), SelectionForeColor = Ui.Ink, Padding = new Padding(6) };
        _grid.RowTemplate.Height = 40;
        _grid.Columns.Add(TextColumn("Имя пользователя", 150));
        _grid.Columns.Add(CheckColumn("Заблокирован"));
        _grid.Columns.Add(CheckColumn("Ограничения пароля"));
        _grid.Columns.Add(TextColumn("Минимальная длина", 95));
        _grid.Columns.Add(TextColumn("Срок действия (месяцы)", 110));
        _grid.Columns.Add(TextColumn("Последняя смена пароля", 175));
        _grid.Columns.Add(CheckColumn("Пароль установлен"));
        Ui.Row(content, _grid, fill: true);
        var close = Ui.Button("Закрыть");
        close.DialogResult = DialogResult.Cancel;
        Ui.Actions(content, close,
            Ui.Button("Обновить", (_, _) => RefreshUsers()),
            Ui.Button("Блокировка", (_, _) => ToggleBlock()),
            Ui.Button("Параметры", (_, _) => Edit()),
            Ui.Button("Добавить", (_, _) =>
            {
                using var add = new AddUserForm(_accounts);
                if (add.ShowDialog(this) == DialogResult.OK) RefreshUsers();
            }, true));
        CancelButton = close;
        _grid.CellDoubleClick += (_, e) => { if (e.RowIndex >= 0) Edit(); };
        RefreshUsers();
    }

    private static DataGridViewTextBoxColumn TextColumn(string title, int width) => new()
    {
        HeaderText = title, FillWeight = width, MinimumWidth = width,
        SortMode = DataGridViewColumnSortMode.NotSortable
    };
    private static DataGridViewCheckBoxColumn CheckColumn(string title) => new()
    {
        HeaderText = title, FillWeight = 100, MinimumWidth = 100,
        SortMode = DataGridViewColumnSortMode.NotSortable
    };

    private void RefreshUsers()
    {
        string? selected = SelectedUsername;
        if (!Ui.Attempt(this, () =>
        {
            var users = _accounts.GetUsers();
            _grid.Rows.Clear();
            foreach (var user in users)
            {
                int index = _grid.Rows.Add(user.Username, user.IsBlocked, user.PasswordRestrictionsEnabled,
                    user.MinimumPasswordLength, user.PasswordLifetimeMonths,
                    user.PasswordChangedAtUtc?.ToLocalTime().ToString("dd.MM.yyyy HH:mm") ?? "Не установлен", user.PasswordInitialized);
                if (user.Username == selected) _grid.CurrentCell = _grid.Rows[index].Cells[0];
            }
            _count.Text = $"Всего учетных записей: {users.Count}. Выберите строку, чтобы изменить параметры.";
        })) Close();
    }

    private void Edit()
    {
        if (SelectedUsername is not { } username) return;
        using var edit = new UserSettingsForm(_accounts, username);
        if (edit.ShowDialog(this) == DialogResult.OK) RefreshUsers();
    }

    private void ToggleBlock()
    {
        if (SelectedUsername is not { } username) return;
        Ui.Attempt(this, () =>
        {
            var user = _accounts.GetUsers().Single(u => u.Username == username);
            if (user.IsAdministrator) throw new InvalidOperationException("Администратора ADMIN нельзя заблокировать.");
            string action = user.IsBlocked ? "Разблокировать" : "Заблокировать";
            if (!Ui.Confirm(this, $"{action} пользователя «{username}»?")) return;
            _accounts.UpdateUserSettings(username, !user.IsBlocked, user.PasswordRestrictionsEnabled, user.MinimumPasswordLength, user.PasswordLifetimeMonths);
            RefreshUsers();
        });
    }
}
