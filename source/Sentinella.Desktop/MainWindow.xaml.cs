using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;
using Sentinella.App;
using Sentinella.Core;
namespace Sentinella.Desktop;
public record ScanItem(string Label,string Path,string Engine,string Sha256,bool Actionable);
public record ActivityItem(DateTimeOffset Time,string Title,string Detail);
public partial class MainWindow : Window
{
    public ObservableCollection<ScanItem> ScanItems {get;}=[];
    public ObservableCollection<QuarantineEntry> QuarantineItems {get;}=[];
    public ObservableCollection<SnapshotInfo> BackupItems {get;}=[];
    public ObservableCollection<ActivityItem> ActivityItems {get;}=[];
    readonly string runtimeRoot,stateRoot;
    readonly string? previewDirectory;
    readonly string? smokeFile;
    readonly ClamEngine clam;
    CancellationTokenSource? operation;
    string? rulesPath;
    JsonElement? audit;
    ClamStatus? clamStatus;
    object? lastReport;
    FileSystemWatcher? watcher;
    readonly HashSet<string> pending=new(StringComparer.OrdinalIgnoreCase);
    readonly object queueGate=new();
    readonly DispatcherTimer monitorTimer=new(){Interval=TimeSpan.FromSeconds(4)};
    bool ready;
    readonly JsonSerializerOptions jsonOptions=new(){WriteIndented=true};
    CancellationToken Token=>operation?.Token??CancellationToken.None;
    public MainWindow(string runtimeRoot,string stateRoot,string? previewDirectory=null,string? smokeFile=null)
    {
        this.runtimeRoot=runtimeRoot; this.stateRoot=stateRoot; this.previewDirectory=previewDirectory; this.smokeFile=smokeFile;
        clam=new ClamEngine(Path.Combine(runtimeRoot,"clamav"),Path.Combine(runtimeRoot,"database"));
        InitializeComponent(); DataContext=this;
        MaxHeight=SystemParameters.WorkArea.Height; MaxWidth=SystemParameters.WorkArea.Width;
        Height=Math.Min(940,SystemParameters.WorkArea.Height-20); Width=Math.Min(1360,SystemParameters.WorkArea.Width-20);
        monitorTimer.Tick+=async(_,_)=>await PollMonitor();
        Closing+=(_,e)=>{if(operation!=null){e.Cancel=true; operation.Cancel(); TaskStatus.Text="Attendi la conclusione, poi chiudi.";}else{monitorTimer.Stop();watcher?.Dispose();}};
        ready=true;
    }
    async void WindowLoaded(object sender,RoutedEventArgs e)
    {
        await Work("Lettura delle protezioni",RefreshAll);
        RefreshStores();
        if(smokeFile is not null){TargetPath.Text=smokeFile; await Work("Scansione di verifica UI",()=>ScanTarget(smokeFile));}
        if(previewDirectory is not null)
        {
            await Dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);
            await RenderPreviews(previewDirectory);
            Close();
        }
    }
    void Navigate(object sender,RoutedEventArgs e)
    {
        if(!ready||sender is not RadioButton button) return;
        ShowPage(button.Tag?.ToString()??"dashboard");
    }
    void ShowPage(string page)
    {
        var pages=new Dictionary<string,(FrameworkElement Element,string Title)>{["dashboard"]=(DashboardPage,"Panoramica"),["scan"]=(ScanPage,"Scansioni"),["protection"]=(ProtectionPage,"Protezioni"),["quarantine"]=(QuarantinePage,"Quarantena"),["backup"]=(BackupPage,"Backup dei file"),["activity"]=(ActivityPage,"Attività"),["settings"]=(SettingsPage,"Impostazioni")};
        foreach(var item in pages) item.Value.Element.Visibility=item.Key==page?Visibility.Visible:Visibility.Collapsed;
        PageLabel.Text=pages[page].Title; PageScroll.ScrollToTop();
        if(previewDirectory is null) pages[page].Element.BeginAnimation(OpacityProperty,new DoubleAnimation(0.55,1,TimeSpan.FromMilliseconds(160)));
    }
    void GoScan(object sender,RoutedEventArgs e)=>NavScan.IsChecked=true;
    void GoProtection(object sender,RoutedEventArgs e)=>NavProtection.IsChecked=true;
    void GoBackup(object sender,RoutedEventArgs e)=>NavBackup.IsChecked=true;
    void GoActivity(object sender,RoutedEventArgs e)=>NavActivity.IsChecked=true;
    void TitleDrag(object sender,MouseButtonEventArgs e){if(e.OriginalSource is Button)return; if(e.ClickCount==2)WindowState=WindowState==WindowState.Maximized?WindowState.Normal:WindowState.Maximized;else if(e.LeftButton==MouseButtonState.Pressed)DragMove();}
    void Minimize(object sender,RoutedEventArgs e)=>WindowState=WindowState.Minimized;
    void Maximize(object sender,RoutedEventArgs e)=>WindowState=WindowState==WindowState.Maximized?WindowState.Normal:WindowState.Maximized;
    void CloseWindow(object sender,RoutedEventArgs e)=>Close();
    void CancelOperation(object sender,RoutedEventArgs e)=>operation?.Cancel();
    async Task Work(string title,Func<Task> action)
    {
        if(operation!=null){TaskStatus.Text="È già in corso un'operazione.";return;}
        operation=new CancellationTokenSource(); BusyProgress.Visibility=CancelButton.Visibility=Visibility.Visible; StartScanButton.IsEnabled=false;
        TaskStatus.Text=title; TaskDot.Fill=new SolidColorBrush(Color.FromRgb(59,120,245));
        try{await action();TaskStatus.Text="Operazione completata";}
        catch(OperationCanceledException){Record(title,"Interrotta: il servizio Windows può continuare una scansione già avviata.");TaskStatus.Text="Operazione interrotta";}
        catch(Exception ex){Record(title,"Errore: "+ex.Message);DiagnosticText.Text=ex.ToString();TaskStatus.Text="Errore · apri Attività per i dettagli";}
        finally{operation.Dispose();operation=null;BusyProgress.Visibility=CancelButton.Visibility=Visibility.Collapsed;StartScanButton.IsEnabled=true;TaskDot.Fill=new SolidColorBrush(Color.FromRgb(94,170,139));}
    }
    void Record(string title,string detail)
    {
        ActivityItems.Insert(0,new(DateTimeOffset.Now,title,detail)); while(ActivityItems.Count>400)ActivityItems.RemoveAt(ActivityItems.Count-1);
        RecentActivity.Text=title+" · "+detail;
        if(previewDirectory is not null)return;
        try{Directory.CreateDirectory(stateRoot);string tmp=Path.Combine(stateRoot,"activity.tmp");File.WriteAllText(tmp,JsonSerializer.Serialize(ActivityItems,jsonOptions));File.Move(tmp,Path.Combine(stateRoot,"activity.json"),true);}catch(Exception ex){TaskStatus.Text="Registro non salvato: "+ex.Message;}
    }
    void RefreshStores()
    {
        try{QuarantineItems.Clear();foreach(var e in Store().List())QuarantineItems.Add(e);QuarantineValue.Text=$"{QuarantineItems.Count} elementi";}catch(Exception ex){QuarantineValue.Text="Non disponibile";Record("Quarantena",ex.Message);}
        try{BackupItems.Clear();foreach(var e in Vault().List())BackupItems.Add(e);}catch(Exception ex){Record("Backup",ex.Message);}
        if(previewDirectory is null&&ActivityItems.Count==0)
        {try{string p=Path.Combine(stateRoot,"activity.json");if(File.Exists(p)&&new FileInfo(p).Length<4*1024*1024){foreach(var item in JsonSerializer.Deserialize<List<ActivityItem>>(File.ReadAllText(p))??[])ActivityItems.Add(item);if(ActivityItems.FirstOrDefault() is{}last)RecentActivity.Text=last.Title+" · "+last.Detail;}}catch(Exception ex){TaskStatus.Text="Cronologia non disponibile: "+ex.Message;}}
    }
    QuarantineStore Store()=>new(Path.Combine(stateRoot,"quarantine"));
    SnapshotVault Vault()=>new(Path.Combine(stateRoot,"snapshots"));
    async void RefreshClick(object sender,RoutedEventArgs e)=>await Work("Aggiornamento stato",RefreshAll);
    async Task RefreshAll()
    {
        var a=ProtectionTools.GetAuditAsync(Token);var c=clam.GetStatusAsync(Token);await Task.WhenAll(a,c);audit=await a;clamStatus=await c;
        var s=clamStatus;
        EngineValue.Text=s.EngineAvailable?s.EngineVersion.Split('/')[0]:"Non disponibile";
        EngineHint.Text=s.OfficialDatabasesPresent?$"{s.SignatureCount:N0} firme dichiarate":s.DatabaseAvailable?"Firme parziali o personali":"Firme mancanti";
        ScanEngineStatus.Text=s.EngineAvailable&&s.DatabaseAvailable?$"{s.EngineVersion} · {s.SignatureCount:N0} firme dichiarate · {(s.OfficialDatabasesPresent?"database ufficiali presenti":"copertura parziale")}":s.Detail;
        ClamDetails.Text=$"{s.EngineVersion}\n{s.Detail}\nFirme dichiarate: {s.SignatureCount:N0}\nAggiornamento database: {s.DatabaseUpdatedAt?.ToLocalTime().ToString("g")??"non disponibile"}\nDirectory: {clam.DatabaseDirectory}";
        ApplyAudit(audit.Value);LastCheck.Text="Letto alle "+DateTime.Now.ToString("HH:mm");
    }
    static bool Available(JsonElement section)=>section.TryGetProperty("Available",out var b)&&b.ValueKind==JsonValueKind.True;
    static string PolicyName(JsonElement values,string property)
    {if(!values.TryGetProperty(property,out var p)||p.ValueKind==JsonValueKind.Null)return"Non disponibile";var n=p.GetInt32();return n==1?"Configurata: attiva":n==2?"Configurata: audit":n==0?"Configurata: disattiva":"Modalità "+n;}
    void ApplyAudit(JsonElement data)
    {
        var def=data.GetProperty("Defender");
        if(Available(def))
        {
            var d=def.GetProperty("Values");bool rt=d.GetProperty("RealTimeProtectionEnabled").ValueKind==JsonValueKind.True;
            RealtimeValue.Text=rt?"Defender attivo":"Verifica provider";RealtimeHint.Text=d.GetProperty("RunningMode").GetString()??"Modalità non disponibile";
            HeroStatus.Text=rt?"DEFENDER IN TEMPO REALE ATTIVO":"TEMPO REALE DA VERIFICARE";
            HeroDescription.Text=rt?"La protezione Windows è attiva. Affiancala a scansioni e controlli indipendenti.":"Defender non riporta il tempo reale attivo. Verifica quale provider installato protegge il PC.";
            RansomwareState.Text=PolicyName(d,"ControlledFolderAccess");AdditionalState.Text="Applicazioni indesiderate: "+PolicyName(d,"PuaProtection")+"\nProtezione di rete: "+PolicyName(d,"NetworkProtection");
        }
        else{RealtimeValue.Text="Non disponibile";RealtimeHint.Text="Lettura Windows non riuscita";HeroStatus.Text="STATO WINDOWS NON DISPONIBILE";RansomwareState.Text="Stato non disponibile";AdditionalState.Text="Stato non disponibile";}
        var providers=data.GetProperty("Providers");ProviderDetails.Text=Available(providers)?string.Join(" · ",providers.GetProperty("Items").EnumerateArray().Select(x=>x.GetProperty("DisplayName").GetString()))+"\nLa registrazione di un provider non dimostra da sola che tutte le sue protezioni siano operative.":"Elenco provider non disponibile.";
        var firewall=data.GetProperty("Firewall");
        if(Available(firewall))
        {var items=firewall.GetProperty("Items").EnumerateArray().ToArray();int count=items.Count(x=>x.GetProperty("Enabled").ValueKind==JsonValueKind.True);FirewallValue.Text=$"{count}/{items.Length} attivi";FirewallHint.Text="Profili Windows osservati";FirewallState.Text=string.Join(" · ",items.Select(x=>x.GetProperty("Name").GetString()+": "+(x.GetProperty("Enabled").ValueKind==JsonValueKind.True?"attivo":"spento")));}
        else{FirewallValue.Text="Non disponibile";FirewallState.Text="Lettura firewall non riuscita";}
    }
    void BrowseFile(object sender,RoutedEventArgs e){var d=new OpenFileDialog{Title="Seleziona un file da analizzare"};if(d.ShowDialog(this)==true)TargetPath.Text=d.FileName;}
    void BrowseFolder(object sender,RoutedEventArgs e){var d=new OpenFolderDialog{Title="Seleziona una cartella da analizzare"};if(d.ShowDialog(this)==true)TargetPath.Text=d.FolderName;}
    async void ScanClick(object sender,RoutedEventArgs e)=>await Work("Scansione in corso",()=>ScanTarget(TargetPath.Text));
    async Task ScanTarget(string target)
    {
        ScanItems.Clear();
        if(ChooseClam.IsChecked==true)
        {
            var report=await clam.ScanAsync(target,Token,new Progress<string>(s=>TaskStatus.Text=s.Length>115?s[..115]+"…":s)); lastReport=report;
            foreach(var d in report.Detections)ScanItems.Add(new(d.IsHeuristicWarning?"Non ispezionabile":d.Signature,d.Path,"ClamAV","",!d.IsHeuristicWarning));
            ScanSummary.Text=$"{report.ScannedFiles:N0} file analizzati · {report.Detections.Count(d=>!d.IsHeuristicWarning)} rilevamenti · {(report.IsComplete?"analisi terminata":"analisi incompleta")}";
            if(report.Detections.Count==0)ScanSummary.Text+="\n"+(report.Verdict=="NoDetectionsWithinScope"?"Nessun rilevamento nel perimetro analizzato.":"Il risultato non permette di escludere minacce.");
            if(report.Warnings.Count>0)ScanSummary.Text+="\n"+string.Join("\n",report.Warnings.Take(5));
            DiagnosticText.Text=(report.Output+"\n"+report.StandardError)[..Math.Min(report.Output.Length+report.StandardError.Length+1,120000)];
            Record("Scansione ClamAV",ScanSummary.Text);
        }
        else if(ChooseDefender.IsChecked==true)
        {
            var result=await WindowsSecurity.ScanAsync(target,3,Token);lastReport=result;DiagnosticText.Text=result.Output+"\n"+result.StandardError;
            ScanSummary.Text=$"Defender ha restituito il codice {result.ExitCode}. "+(result.ExitCode==0?"Operazione terminata. Consulta l'output completo in Attività.":"Attenzione: possibile errore, rilevamento o intervento richiesto. Consulta Attività.");
            Record("Scansione Defender",ScanSummary.Text);
        }
        else
        {
            var scanner=new LocalScanner(rulesPath);var report=await scanner.ScanAsync(target,Token);lastReport=report;
            foreach(var f in report.Findings)ScanItems.Add(new(f.Verdict=="LocalHashMatch"?f.Detail:"Nessuna corrispondenza locale",f.Path,"Hash",f.Sha256,f.Verdict=="LocalHashMatch"));
            ScanSummary.Text=$"{report.FilesScanned:N0} file · {report.FilesSkipped} esclusi · {report.Findings.Count(x=>x.Verdict=="LocalHashMatch")} corrispondenze · {report.Errors.Count} errori. "+(scanner.RuleCount==0?"Non sono state caricate firme personali.":"Nessuna corrispondenza locale non significa file sicuro.");
            DiagnosticText.Text=string.Join("\n",report.Errors);Record("Scansione hash",ScanSummary.Text);
        }
    }
    async void UpdateClamClick(object sender,RoutedEventArgs e)=>await Work("Aggiornamento database ClamAV",async()=>
    {
        var result=await clam.UpdateAsync(Token,new Progress<string>(s=>TaskStatus.Text=s.Length>115?s[..115]+"…":s));DiagnosticText.Text=result.Output+"\n"+result.StandardError;lastReport=result;
        Record("Firme ClamAV",result.ExitCode==0?"Aggiornamento completato.":"Aggiornamento non completato: codice "+result.ExitCode+". Consulta output e riprova dopo l'eventuale intervallo imposto dal server.");await RefreshAll();
    });
    async void ImportHash(object sender,RoutedEventArgs e)=>await Work("Importazione regole",()=>
    {var dialog=new OpenFileDialog{Title="Importa regole SHA-256",Filter="Regole JSON|*.json"};if(dialog.ShowDialog(this)!=true)return Task.CompletedTask;var scanner=new LocalScanner(dialog.FileName);rulesPath=dialog.FileName;RuleHint.Text=$"{scanner.RuleCount:N0} regole personali · {Path.GetFileName(rulesPath)}";Record("Regole hash",$"Caricate {scanner.RuleCount} regole locali.");return Task.CompletedTask;});
    async void QuarantineSelected(object sender,RoutedEventArgs e)=>await Work("Verifica e isolamento",async()=>
    {
        if(ScanResults.SelectedItem is not ScanItem item||!item.Actionable)throw new InvalidOperationException("Seleziona un rilevamento confermato, non una limitazione dell'analisi.");
        QuarantineEntry entry;
        if(item.Engine=="ClamAV")entry=await ClamQuarantine.IsolateAsync(clam,Store(),item.Path,Path.Combine(stateRoot,"scan-staging"),Token);
        else if(item.Engine=="Hash")entry=await Store().QuarantineAsync(new Finding(item.Path,item.Sha256,"LocalHashMatch",item.Label));
        else throw new InvalidOperationException("Gestisci le rilevazioni Defender in Sicurezza di Windows.");
        Record("Quarantena","Isolato: "+entry.OriginalPath);RefreshStores();
    });
    async void RestoreQuarantine(object sender,RoutedEventArgs e)=>await Work("Ripristino da quarantena",async()=>
    {
        if(QuarantineGrid.SelectedItem is not QuarantineEntry entry)throw new InvalidOperationException("Seleziona un elemento della quarantena.");
        var d=new SaveFileDialog{Title="Ripristina una copia in un nuovo file",FileName=Path.GetFileName(entry.OriginalPath),OverwritePrompt=true};if(d.ShowDialog(this)!=true)return;
        await Store().RestoreAsync(entry.Id,d.FileName);Record("Ripristino",d.FileName);RefreshStores();
    });
    void OpenWindowsSecurity(object sender,RoutedEventArgs e){try{WindowsSecurity.OpenSecurity();}catch(Exception ex){Record("Sicurezza di Windows",ex.Message);}}
    async void ApplyPolicy(object sender,RoutedEventArgs e)=>await Work("Modifica della protezione Windows",async()=>
    {
        string action=(sender as Button)?.Tag?.ToString()??throw new InvalidOperationException("Azione mancante");
        await ProtectionTools.ApplyPolicyAsync(action,Token);Record("Protezione Windows",action+": preferenza configurata. Verifica l'operatività con il provider attivo.");await RefreshAll();
    });
    async void QuickDefender(object sender,RoutedEventArgs e)=>await DefenderOperation(1);
    async void FullDefender(object sender,RoutedEventArgs e)=>await DefenderOperation(2);
    Task DefenderOperation(int type)=>Work("Scansione Defender",async()=>{var r=await WindowsSecurity.ScanAsync(null,type,Token);lastReport=r;DiagnosticText.Text=r.Output+"\n"+r.StandardError;Record("Defender","Codice "+r.ExitCode+". Consulta l'output completo.");});
    async void UpdateDefender(object sender,RoutedEventArgs e)=>await Work("Aggiornamento Defender",async()=>{var r=await WindowsSecurity.UpdateAsync(Token);lastReport=r;DiagnosticText.Text=r.Output+"\n"+r.StandardError;Record("Firme Defender","Codice "+r.ExitCode);await RefreshAll();});
    async void CreateBackup(object sender,RoutedEventArgs e)=>await Work("Creazione backup",async()=>
    {
        var d=new OpenFolderDialog{Title="Seleziona la cartella da salvare"};if(d.ShowDialog(this)!=true)return;
        var info=await Vault().CreateAsync(d.FolderName,Token,new Progress<string>(s=>TaskStatus.Text="Backup · "+Path.GetFileName(s)));
        Record("Backup",$"{info.FileCount} file salvati · {(info.Complete?"completo":"incompleto")}");DiagnosticText.Text=string.Join("\n",info.Errors);RefreshStores();
    });
    async void RestoreBackup(object sender,RoutedEventArgs e)=>await Work("Ripristino backup",async()=>
    {
        if(BackupGrid.SelectedItem is not SnapshotInfo info)throw new InvalidOperationException("Seleziona una versione da ripristinare.");
        var d=new OpenFolderDialog{Title="Scegli la cartella dove creare una nuova sottocartella di ripristino"};if(d.ShowDialog(this)!=true)return;
        string destination=Path.Combine(d.FolderName,"Sentinella-ripristino-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+"-"+Guid.NewGuid().ToString("N")[..6]);
        await Vault().RestoreAsync(info.Id,destination,Token);Record("Ripristino backup",destination);
    });
    async void AuditStartup(object sender,RoutedEventArgs e)=>await Work("Inventario avvio",async()=>{audit=await ProtectionTools.GetAuditAsync(Token);DiagnosticText.Text=JsonSerializer.Serialize(audit.Value.GetProperty("Startup"),jsonOptions);Record("Inventario avvio","Elenco letto. La presenza di una voce non dimostra una minaccia.");});
    async void AuditConnections(object sender,RoutedEventArgs e)=>await Work("Connessioni Windows",async()=>{audit=await ProtectionTools.GetAuditAsync(Token);DiagnosticText.Text=JsonSerializer.Serialize(audit.Value.GetProperty("Connections"),jsonOptions);Record("Connessioni","Snapshot TCP letto. Un indirizzo remoto non implica un'attività malevola.");});
    async void ExportReport(object sender,RoutedEventArgs e)=>await Work("Esportazione rapporto",async()=>
    {
        var d=new SaveFileDialog{Filter="Rapporto JSON|*.json",FileName="Sentinella-"+DateTime.Now.ToString("yyyyMMdd-HHmmss")+".json"};if(d.ShowDialog(this)!=true)return;
        var report=new{Product="Sentinella 0.2",ExportedAt=DateTimeOffset.Now,Windows=audit,Engine=clamStatus,LastScan=lastReport,Activity=ActivityItems,Limits="No equivalence claim; Windows monitor is post-write, not execution prevention."};
        await File.WriteAllTextAsync(d.FileName,JsonSerializer.Serialize(report,jsonOptions),Token);Record("Rapporto esportato",d.FileName);
    });
    async void StartMonitor(object sender,RoutedEventArgs e)=>await Work("Avvio monitor",async()=>
    {
        var status=await clam.GetStatusAsync(Token);if(!status.EngineAvailable||!status.OfficialDatabasesPresent)throw new InvalidOperationException("Per il monitor servono il motore e i database ufficiali ClamAV.");
        var d=new OpenFolderDialog{Title="Cartella da monitorare con ClamAV"};if(d.ShowDialog(this)!=true)return;
        if((File.GetAttributes(d.FolderName)&FileAttributes.ReparsePoint)!=0)throw new IOException("Scegli una cartella reale, senza collegamenti.");
        StopWatcher();watcher=new FileSystemWatcher(d.FolderName){IncludeSubdirectories=true,NotifyFilter=NotifyFilters.FileName|NotifyFilters.LastWrite,InternalBufferSize=16384};
        watcher.Created+=Queue;watcher.Changed+=Queue;watcher.Renamed+=Queue;
        watcher.Error+=(_,args)=>Dispatcher.InvokeAsync(()=>Record("Monitor incompleto",args.GetException().Message+". Esegui una scansione manuale."));
        watcher.EnableRaisingEvents=true;monitorTimer.Start();MonitorState.Text="Monitor attivo · "+d.FolderName;Record("Monitor avviato",d.FolderName);
    });
    bool queueOverflow;
    void Queue(object sender,FileSystemEventArgs e){lock(queueGate){if(pending.Count<500)pending.Add(e.FullPath);else queueOverflow=true;}}
    void StopWatcher(){monitorTimer.Stop();watcher?.Dispose();watcher=null;lock(queueGate){pending.Clear();queueOverflow=false;}MonitorState.Text="Monitor fermo";}
    void StopMonitor(object sender,RoutedEventArgs e){StopWatcher();Record("Monitor","Fermato dall'utente.");}
    async Task PollMonitor()
    {
        if(operation is not null)return;List<string> files;bool overflow;
        lock(queueGate){files=pending.Take(3).ToList();foreach(var p in files)pending.Remove(p);overflow=queueOverflow;queueOverflow=false;}
        if(overflow)Record("Monitor incompleto","Coda piena: alcuni eventi sono stati esclusi. Avvia una scansione manuale.");
        if(files.Count==0)return;
        await Work("Controllo file in coda",async()=>
        {
            foreach(string path in files)
            {
                if(!File.Exists(path))continue;
                try
                {
                    var report=await clam.ScanAsync(path,Token);lastReport=report;
                    if(report.Detections.Count>0){foreach(var d in report.Detections)ScanItems.Add(new(d.Signature,d.Path,"ClamAV","",!d.IsHeuristicWarning));Record("Monitor · rilevamento",path);}
                    else if(!report.IsComplete)Record("Monitor incompleto",path+": "+string.Join("; ",report.Warnings.Take(2)));
                }
                catch(OperationCanceledException){throw;}
                catch(Exception ex){Record("Monitor · errore",path+": "+ex.Message);}
            }
        });
    }
    public async Task RenderPreviews(string directory)
    {
        Directory.CreateDirectory(directory);
        var nav=new[]{NavDashboard,NavScan,NavProtection,NavQuarantine,NavBackup,NavActivity,NavSettings};
        for(int i=0;i<nav.Length;i++)
        {
            nav[i].IsChecked=true;UpdateLayout();await Dispatcher.InvokeAsync(()=>{},DispatcherPriority.ApplicationIdle);
            var bitmap=new RenderTargetBitmap((int)Math.Ceiling(ActualWidth*1.5),(int)Math.Ceiling(ActualHeight*1.5),144,144,PixelFormats.Pbgra32);bitmap.Render(this);
            var png=new PngBitmapEncoder();png.Frames.Add(BitmapFrame.Create(bitmap));using var output=File.Create(Path.Combine(directory,$"preview-{i}.png"));png.Save(output);
        }
        File.WriteAllText(Path.Combine(directory,"observed.json"),JsonSerializer.Serialize(new{Engine=clamStatus,Audit=audit,Width=ActualWidth,Height=ActualHeight},jsonOptions));
    }
}


