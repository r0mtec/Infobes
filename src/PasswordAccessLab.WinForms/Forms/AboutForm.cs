namespace PasswordAccessLab.WinForms.Forms;

internal sealed class AboutForm : StyledForm
{
    public AboutForm() : base("О программе", new Size(690, 570))
    {
        var content = Ui.Content(this);
        Ui.Row(content, Ui.Label("Лабораторная работа №1", true));
        Ui.Row(content, Ui.Label(AppInfo.LaboratoryTitle));
        Ui.Row(content, Ui.Label($"Автор: {AppInfo.AuthorFullName}\nИндивидуальный вариант: №2"));
        Ui.Row(content, Ui.Label("Парольные ограничения: латинские буквы, кириллица, арифметические знаки (+ - * /)."));
        Ui.Row(content, Ui.Label("Шифрование: DES-CBC, дополнение PKCS7.\nСлучайное добавление к ключу: нет.\nХеширование паролей: MD5."));
        var close = Ui.Button("Закрыть", primary: true);
        close.DialogResult = DialogResult.OK;
        Ui.Actions(content, close);
        AcceptButton = close;
        CancelButton = close;
    }
}
