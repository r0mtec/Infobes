using System.Drawing;

namespace PasswordAccessLab.WinForms.Forms;

internal static class Ui
{
    public static readonly Color Background = Color.FromArgb(245, 247, 251);
    public static readonly Color Ink = Color.FromArgb(29, 43, 66);
    public static readonly Color Muted = Color.FromArgb(91, 106, 128);
    public static readonly Color Accent = Color.FromArgb(38, 93, 192);

    public static TableLayoutPanel Content(Control parent, int padding = 28)
    {
        var panel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 0,
            Padding = new Padding(padding), BackColor = Background, AutoScroll = true
        };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        parent.Controls.Add(panel);
        return panel;
    }

    public static void Row(TableLayoutPanel panel, Control control, bool fill = false)
    {
        int row = panel.RowCount++;
        panel.RowStyles.Add(new RowStyle(fill ? SizeType.Percent : SizeType.AutoSize, fill ? 100 : 0));
        control.Dock = fill ? DockStyle.Fill : DockStyle.Top;
        panel.Controls.Add(control, 0, row);
    }

    public static Label Label(string text, bool title = false) => new()
    {
        Text = text, AutoSize = true, ForeColor = title ? Ink : Muted,
        Font = new Font("Segoe UI", title ? 19 : 10.5f, title ? FontStyle.Bold : FontStyle.Regular),
        Margin = new Padding(0, 0, 0, title ? 12 : 16), MaximumSize = new Size(1100, 0)
    };

    public static TextBox Input(bool secret = false) => new()
    {
        PasswordChar = secret ? '*' : '\0', BorderStyle = BorderStyle.FixedSingle,
        Margin = new Padding(0, 0, 0, 16), Dock = DockStyle.Top,
        AccessibleName = secret ? "Пароль" : "Текст"
    };

    public static void Field(TableLayoutPanel panel, string text, Control input)
    {
        var label = Label(text);
        label.Margin = new Padding(0, 0, 0, 6);
        input.AccessibleName = text;
        Row(panel, label);
        Row(panel, input);
    }

    public static Button Button(string text, EventHandler? click = null, bool primary = false)
    {
        var button = new Button
        {
            Text = text, AutoSize = true, MinimumSize = new Size(110, 38),
            Padding = new Padding(12, 5, 12, 5), FlatStyle = FlatStyle.Flat,
            BackColor = primary ? Accent : Color.White,
            ForeColor = primary ? Color.White : Ink,
            Cursor = Cursors.Hand, Margin = new Padding(8, 4, 0, 4),
            UseVisualStyleBackColor = false
        };
        button.FlatAppearance.BorderColor = primary ? Accent : Color.FromArgb(207, 215, 228);
        if (click is not null) button.Click += click;
        return button;
    }

    public static void Actions(TableLayoutPanel panel, params Button[] buttons)
    {
        var bar = new FlowLayoutPanel
        {
            AutoSize = true, FlowDirection = FlowDirection.RightToLeft,
            WrapContents = true, Margin = new Padding(0, 12, 0, 0), Dock = DockStyle.Fill
        };
        bar.Controls.AddRange(buttons);
        Row(panel, bar);
    }

    public static void Error(IWin32Window owner, Exception exception) =>
        MessageBox.Show(owner, exception.Message, "Не удалось выполнить действие", MessageBoxButtons.OK, MessageBoxIcon.Error);

    public static bool Attempt(IWin32Window owner, Action action)
    {
        try { action(); return true; }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or UnauthorizedAccessException or IOException or InvalidDataException or System.Security.Cryptography.CryptographicException)
        {
            Error(owner, ex);
            return false;
        }
    }

    public static bool Confirm(IWin32Window owner, string message) =>
        MessageBox.Show(owner, message, "Подтверждение", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
            MessageBoxDefaultButton.Button2) == DialogResult.Yes;
}

internal class StyledForm : Form
{
    public StyledForm(string title, Size size, bool resizable = false)
    {
        AutoScaleDimensions = new SizeF(96, 96);
        AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 10.5f);
        ForeColor = Ui.Ink;
        BackColor = Ui.Background;
        Text = title;
        ClientSize = size;
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = resizable ? FormBorderStyle.Sizable : FormBorderStyle.FixedDialog;
        MaximizeBox = resizable;
        MinimizeBox = resizable;
        ShowIcon = false;
    }
}
