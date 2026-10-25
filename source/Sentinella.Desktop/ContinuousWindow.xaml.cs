using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using Sentinella.App;
using Sentinella.Core;
namespace Sentinella.Desktop;
public partial class ContinuousWindow : Window
{
    readonly string state, runtime; readonly Action<string> scan; readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(2) }; bool busy;
    public ContinuousWindow(string state, string runtime, Action<string> scan)
    {
        this.state = state; this.runtime = runtime; this.scan = scan; InitializeComponent();
        var config = ContinuousConfiguration.Load(AgentClient.Config(state)); foreach (string path in config.Folders) FolderList.Items.Add(path);
        AutoDefinitions.IsChecked = config.AutoUpdateSignatures; ObserveProcesses.IsChecked = config.ObserveProcesses;
        using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run")) StartAtLogon.IsChecked = key?.GetValue("SentinellaFreeUserAgent") is string;
        timer.Tick += (_, _) => Refresh(); Loaded += (_, _) => { Refresh(); timer.Start(); }; Closed += (_, _) => timer.Stop();
        Closing += (_, e) => { if (busy) e.Cancel = true; };
    }
    void Refresh()
    {
        try
        {
            var snapshot = AgentClient.Read(state);
            bool fresh = snapshot is not null && DateTimeOffset.UtcNow - snapshot.Heartbeat < TimeSpan.FromSeconds(12);
            AgentStatus.Text = !fresh ? "Agente fermo o stato non aggiornato" : snapshot!.State switch { "MonitoringAfterWrite" => "Monitor dopo scrittura in esecuzione", "UpdatingSignatures" => "Aggiornamento firme in corso", "Stopping" => "Arresto in corso", "Starting" => "Avvio in corso", "Stopped" => "Agente fermo", _ => "Agente non operativo" };
            AgentDetails.Text = snapshot is null ? "Nessun avvio registrato." : $"Ultimo contatto: {snapshot.Heartbeat.ToLocalTime():T} · analizzati: {snapshot.Scanned} · rilevamenti: {snapshot.Detections} · incompleti: {snapshot.Incomplete} · in coda: {snapshot.Pending}\n{snapshot.Error}";
            AlertGrid.ItemsSource = snapshot?.Alerts;
        }
        catch (Exception ex) { AgentStatus.Text = "Stato non verificabile"; AgentDetails.Text = ex.Message; }
    }
    async Task Work(Func<Task> action)
    {
        if (busy) return; busy = true; IsEnabled = false;
        try { await action(); } catch (Exception ex) { OperationResult.Text = ex.Message; } finally { busy = false; IsEnabled = true; Refresh(); }
    }
    void AddFolder(object sender, RoutedEventArgs e)
    {
        if (FolderList.Items.Count >= 8) { OperationResult.Text = "Limite di otto cartelle."; return; }
        var picker = new OpenFolderDialog { Title = "Cartella per scansioni successive alle modifiche" };
        if (picker.ShowDialog(this) == true && !FolderList.Items.Cast<string>().Contains(picker.FolderName, StringComparer.OrdinalIgnoreCase)) FolderList.Items.Add(picker.FolderName);
    }
    void RemoveFolder(object sender, RoutedEventArgs e) { if (FolderList.SelectedItem is string item) FolderList.Items.Remove(item); }
    async void StartAgent(object sender, RoutedEventArgs e)
    {
        var config = new ContinuousSettings(true, FolderList.Items.Cast<string>().ToList(), AutoDefinitions.IsChecked == true, ObserveProcesses.IsChecked == true);
        try { ContinuousConfiguration.Validate(config); } catch (Exception ex) { OperationResult.Text = ex.Message; return; }
        bool logon = StartAtLogon.IsChecked == true;
        if (MessageBox.Show(this, $"Avviare il monitor dopo scrittura per {config.Folders.Count} cartelle?\nAggiornamenti firme in rete: {config.AutoUpdateSignatures}\nOsservazione processi: {config.ObserveProcesses}\nAvvio al tuo accesso: {logon}\n\nRestera attivo dopo la chiusura della finestra, ma non blocca prima dell'esecuzione e non sostituisce l'antivirus. Nessuna modifica a Smart App Control o agli altri provider.", "Avvio monitor", MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await Work(async () => { await AgentClient.Start(state, runtime, config); AgentClient.SetLogon(logon, state, runtime); OperationResult.Text = "Agente avviato. I file esistenti richiedono una scansione manuale; controlla eventuali avvisi di copertura."; });
    }
    async void StopAgent(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Fermare l'agente e rimuovere il suo avvio automatico? Le scansioni delle cartelle si interromperanno. L'antivirus del sistema rimane invariato.", "Arresto monitor", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) != MessageBoxResult.Yes) return;
        await Work(async () => { AgentClient.SetLogon(false, state, runtime); StartAtLogon.IsChecked = false; await AgentClient.Stop(state); OperationResult.Text = "Arresto richiesto: verifica lo stato aggiornato."; });
    }
    void GoToScan(object sender, RoutedEventArgs e)
    {
        if (AlertGrid.SelectedItem is ProtectionAlert item && File.Exists(item.Subject)) { scan(item.Subject); Close(); }
        else OperationResult.Text = "Seleziona un avviso relativo a un file esistente.";
    }
    async void ReadWindows(object sender, RoutedEventArgs e) => await Work(async () =>
    {
        var audit = await ProtectionTools.GetAuditAsync(); var providers = audit.GetProperty("Providers"); var defender = audit.GetProperty("Defender");
        string names = providers.GetProperty("Available").GetBoolean() ? string.Join(", ", providers.GetProperty("Items").EnumerateArray().Select(p => p.GetProperty("DisplayName").GetString())) : "non leggibili";
        WindowsDetails.Text = "Provider registrati: " + names + ". La registrazione non prova l'efficacia.\n";
        if (defender.GetProperty("Available").GetBoolean()) { var values = defender.GetProperty("Values"); WindowsDetails.Text += "Defender: " + values.GetProperty("RunningMode").GetString() + "; tempo reale dichiarato: " + values.GetProperty("RealTimeProtectionEnabled").GetBoolean(); }
        else WindowsDetails.Text += "Stato Defender non disponibile.";
    });
    void OpenExtension(object sender, RoutedEventArgs e)
    {
        try { string path = Path.Combine(AppContext.BaseDirectory, "browser-extension"); if (!Directory.Exists(path)) throw new DirectoryNotFoundException("Estensione non inclusa in questa cartella di build."); Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
        catch (Exception ex) { OperationResult.Text = ex.Message; }
    }
    void ExtensionHelp(object sender, RoutedEventArgs e) => MessageBox.Show(this, "Nel browser apri la pagina Estensioni. Per questa versione di sviluppo, usa Carica estensione non pacchettizzata e seleziona la cartella browser-extension. Devi autorizzare personalmente i permessi richiesti. Apri poi le opzioni di Sentinella Web: il filtro parte disattivato. Configura e applica domini/liste desiderati. Non e stata installata automaticamente alcuna estensione.", "Filtro web sperimentale");
    async void CheckIntegrity(object sender, RoutedEventArgs e) => await Work(async () => IntegrityResult.Text = await Task.Run(() => InstallationIntegrity.Check(AppContext.BaseDirectory)));
}
