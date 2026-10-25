using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Sentinella.Core;
namespace Sentinella.Desktop;
public partial class AppControlWindow : Window
{
    public ObservableCollection<ApprovedApplication> Approvals { get; } = [];
    readonly string draftPath, runtimeRoot;
    AppControlDraft draft;
    bool busy;
    public AppControlWindow(string stateRoot, string runtimeRoot)
    {
        this.runtimeRoot = runtimeRoot;
        draftPath = Path.Combine(stateRoot, "app-control-draft.json");
        draft = AppControlPolicy.Load(draftPath, AppControlWindows.UserSid);
        InitializeComponent(); DataContext = this; AllowPrograms.IsChecked = draft.AllowProgramFiles;
        foreach (var app in draft.Applications) Approvals.Add(app);
        DraftStatus.Text = $"{Approvals.Count} versioni · utente {draft.UserSid} · bozza locale";
        Loaded += async (_, _) => await Work(Refresh);
        Closing += (_, e) => { if (busy) { e.Cancel = true; ActionResult.Text = "Attendi la conclusione dell'operazione Windows prima di chiudere."; } };
    }
    async Task Work(Func<Task> action)
    {
        if (busy) return; busy = true; IsEnabled = false;
        try { await action(); }
        catch (Exception ex) { ActionResult.Text = ex.Message; }
        finally { IsEnabled = true; busy = false; }
    }
    AppControlDraft Snapshot() => draft with { Applications = Approvals.ToList(), AllowProgramFiles = AllowPrograms.IsChecked == true };
    void BaselineChanged(object sender, RoutedEventArgs e) { if (IsLoaded && !busy) { try { SaveDraft(); } catch (Exception ex) { ActionResult.Text = ex.Message; } } }
    void SaveDraft()
    {
        var next = Snapshot(); AppControlPolicy.Save(draftPath, next); draft = next; AuditReviewed.IsChecked = false;
        DraftStatus.Text = $"{Approvals.Count} versioni · modifiche salvate solo nella bozza, non applicate";
    }
    async Task Add(string path)
    {
        var app = await AppControlWindows.InspectFileAsync(path);
        if (Approvals.Any(a => a.AppLockerHash.Equals(app.AppLockerHash, StringComparison.OrdinalIgnoreCase))) return;
        var next = Snapshot(); next.Applications.RemoveAll(a => a.Path.Equals(app.Path, StringComparison.OrdinalIgnoreCase)); next.Applications.Add(app);
        AppControlPolicy.Validate(next);
        var old = Approvals.FirstOrDefault(a => a.Path.Equals(app.Path, StringComparison.OrdinalIgnoreCase)); if (old is not null) Approvals.Remove(old);
        Approvals.Add(app); SaveDraft();
    }
    async void AddApplication(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog { Filter = "Eseguibili Windows|*.exe;*.com", CheckFileExists = true };
        if (picker.ShowDialog(this) == true) await Work(async () => { await Add(picker.FileName); ActionResult.Text = "Versione aggiunta alla bozza. Nessun criterio Windows modificato."; });
    }
    async void AddEssentials(object sender, RoutedEventArgs e) => await Work(async () =>
    {
        foreach (string path in new[] { AppControlWindows.OwnExecutable, Path.Combine(runtimeRoot, "clamav", "clamscan.exe"), Path.Combine(runtimeRoot, "clamav", "freshclam.exe") })
            if (File.Exists(path)) await Add(path);
        ActionResult.Text = "Componenti esistenti aggiunti alla bozza; dipendenze e nuove versioni vanno verificate separatamente.";
    });
    void RemoveApplication(object sender, RoutedEventArgs e)
    {
        if (busy || ApprovalGrid.SelectedItem is not ApprovedApplication item) return;
        if (MessageBox.Show(this, "Rimuovere questa versione dalla bozza? Il criterio attualmente installato non cambia fino alla nuova applicazione.",
            "Rimuovi autorizzazione", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        var next = Snapshot(); next.Applications.Remove(item); AppControlPolicy.Save(draftPath, next);
        Approvals.Remove(item); draft = next; AuditReviewed.IsChecked = false; DraftStatus.Text = "Rimozione salvata nella bozza; da applicare.";
    }
    async Task Refresh()
    {
        var status = await AppControlWindows.InspectAsync();
        PolicyStatus.Text = "AppLocker EXE: " + status.Mode;
        StatusDetails.Text = $"Application Identity: {status.Service} · avvio {status.StartType}. Stato di configurazione; il blocco sul PC deve essere collaudato.";
        if (status.LocalError is not null) StatusDetails.Text += " Il criterio locale richiede amministratore per essere letto; la verifica completa avviene prima della modifica.";
        SacDetails.Text = "Smart App Control: " + status.SmartAppControl + ". Non viene modificato: puo bloccare un file anche se autorizzato in questa lista.";
    }
    async void RefreshStatus(object sender, RoutedEventArgs e) => await Work(Refresh);
    async void TestApplication(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog { Filter = "Eseguibili Windows|*.exe;*.com", CheckFileExists = true };
        if (picker.ShowDialog(this) == true) await Work(async () => TestResult.Text = await AppControlWindows.EvaluateAsync(Snapshot(), picker.FileName));
    }
    void ExportPlan(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        try
        {
            var picker = new SaveFileDialog { Filter = "Piano JSON|*.json", FileName = "Sentinella-app-control-plan.json" };
            if (picker.ShowDialog(this) != true) return;
            var plan = Snapshot(); if (File.Exists(picker.FileName + ".audit.xml") || File.Exists(picker.FileName + ".enforce.xml")) throw new IOException("I file XML di destinazione esistono gia: scegli un altro nome."); AppControlPolicy.Save(picker.FileName, plan);
            File.WriteAllText(picker.FileName + ".audit.xml", AppControlPolicy.Build(plan));
            File.WriteAllText(picker.FileName + ".enforce.xml", AppControlPolicy.Build(plan, true));
            ActionResult.Text = "Esportati piano, audit e blocco. Contengono SID e percorsi personali: non pubblicarli automaticamente. Nessuna regola installata.";
        }
        catch (Exception ex) { ActionResult.Text = ex.Message; }
    }
    async void ChangePolicy(object sender, RoutedEventArgs e)
    {
        if (busy || sender is not Button button || button.Tag is not string action) return;
        if (action == "Enforce" && AuditReviewed.IsChecked != true) { ActionResult.Text = "Esamina l'audit e conferma la verifica delle applicazioni necessarie."; return; }
        await Work(async () =>
        {
            var plan = Snapshot(); var status = await AppControlWindows.InspectAsync();
            string message = action == "Restore" ? "Ripristinare il criterio precedente salvato da Sentinella? Verranno rimosse le sue restrizioni AppLocker. Smart App Control rimane invariato." :
                $"Utente: {plan.UserSid}\nVersioni approvate: {plan.Applications.Count}\nModalita: {(action == "Audit" ? "AUDIT: registra senza bloccare" : "BLOCCO EXE/COM fuori dalla base Windows e dalle versioni approvate")}\n\nWindows e la base autorizzata. Program Files consentito come base: {plan.AllowProgramFiles}; alcune cartelle Windows scrivibili sono escluse. Script e DLL non sono coperti. Il servizio Application Identity verra configurato per l'avvio automatico. Backup protetto prima di modificare i criteri. Smart App Control rimane invariato. Continuare con la richiesta UAC?";
            if (MessageBox.Show(this, message, "Conferma modifica AppLocker", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
            await AppControlWindows.RequestChangeAsync(new(action, plan, status.Stamp));
            await Refresh(); ActionResult.Text = "Windows ha confermato la configurazione. Verifica gli eventi e un file innocuo prima di considerare collaudato il blocco.";
        });
    }
    void OpenEvents(object sender, RoutedEventArgs e)
    {
        try { Process.Start(new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "eventvwr.exe")) { UseShellExecute = true });
            ActionResult.Text = "Visualizzatore eventi: Registri applicazioni e servizi > Microsoft > Windows > AppLocker > EXE and DLL. Audit: 8003; blocco: 8004."; }
        catch (Exception ex) { ActionResult.Text = ex.Message; }
    }
}
