namespace PasswordAccessLab.WinForms.Forms;

internal sealed class PassphraseForm : StyledForm
{
    private readonly TextBox _phrase = Ui.Input(true);
    private readonly TextBox _confirmation = Ui.Input(true);
    public string Passphrase => _phrase.Text;

    public PassphraseForm(bool firstLaunch) : base(firstLaunch ? "Создание хранилища" : "Открытие хранилища", new Size(580, firstLaunch ? 465 : 375))
    {
        var content = Ui.Content(this);
        Ui.Row(content, Ui.Label(firstLaunch ? "Создайте хранилище" : "Откройте хранилище", true));
        Ui.Row(content, Ui.Label(firstLaunch
            ? "Придумайте и запомните фразу шифрования. Она потребуется при каждом запуске и отличается от пароля учетной записи."
            : "Введите фразу шифрования, выбранную при первом запуске."));
        Ui.Field(content, "Парольная фраза", _phrase);
        if (firstLaunch) Ui.Field(content, "Повторите парольную фразу", _confirmation);
        var submit = Ui.Button(firstLaunch ? "Создать" : "Открыть", (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(_phrase.Text))
            {
                Ui.Error(this, new ArgumentException("Введите непустую парольную фразу."));
                return;
            }
            if (firstLaunch && _phrase.Text != _confirmation.Text)
            {
                Ui.Error(this, new ArgumentException("Парольные фразы не совпадают."));
                return;
            }
            DialogResult = DialogResult.OK;
        }, true);
        var cancel = Ui.Button("Выход");
        cancel.DialogResult = DialogResult.Cancel;
        Ui.Actions(content, submit, cancel);
        AcceptButton = submit;
        CancelButton = cancel;
        Shown += (_, _) => _phrase.Focus();
    }

    public void ClearSecrets()
    {
        _phrase.Clear();
        _confirmation.Clear();
    }
}
