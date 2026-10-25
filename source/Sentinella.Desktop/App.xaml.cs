using System.IO;
using System.Text.Json;
using System.Windows;
namespace Sentinella.Desktop;
public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.FirstOrDefault() == "--app-control-admin")
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try
            {
                if (e.Args.Length != 3) throw new IOException("Richiesta amministratore non valida.");
                await AppControlBroker.RunElevatedAsync(e.Args[1], e.Args[2]);
                MessageBox.Show("Operazione AppLocker completata. Smart App Control non e stato modificato.", "Sentinella", MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown(0);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message + "\n\nAggiorna lo stato. Eventuale backup: ProgramData\\SentinellaFree.AppControl\\original-policy.xml", "Sentinella: modifica non confermata", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown(13);
            }
            return;
        }
        DispatcherUnhandledException += (_, fault) => { int ix=Array.IndexOf(e.Args,"--render-previews"); if(ix>=0 && ix+1<e.Args.Length){Directory.CreateDirectory(e.Args[ix+1]);File.WriteAllText(Path.Combine(e.Args[ix+1],"error.log"),fault.Exception.ToString());fault.Handled=true;Shutdown(1);} else {MessageBox.Show(fault.Exception.Message,"Sentinella",MessageBoxButton.OK,MessageBoxImage.Error);fault.Handled=true;} };
        string runtime = Path.Combine(AppContext.BaseDirectory, "runtime");
        string state = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinellaFree");
        string? preview = null; string? smokeFile = null;
        for(int i=0;i<e.Args.Length;i++)
        {
            if(e.Args[i] == "--runtime-root" && i+1<e.Args.Length) runtime = Path.GetFullPath(e.Args[++i]);
            else if(e.Args[i] == "--state-root" && i+1<e.Args.Length) state = Path.GetFullPath(e.Args[++i]);
            else if(e.Args[i] == "--smoke-file" && i+1<e.Args.Length) smokeFile = Path.GetFullPath(e.Args[++i]);
            else if(e.Args[i] == "--render-previews" && i+1<e.Args.Length) preview = Path.GetFullPath(e.Args[++i]);
        }
        if (e.Args.Contains("--agent"))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try { await BackgroundAgent.Run(state, runtime); Shutdown(0); }
            catch (Exception ex)
            {
                try { Sentinella.Core.AtomicJson.Write(AgentClient.SnapshotPath(state), new Sentinella.Core.ContinuousSnapshot(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, Environment.ProcessId, "Faulted", 0, 0, 0, 0, null, [], ex.Message)); } catch (Exception) { }
                Shutdown(13);
            }
            return;
        }
        var window = new MainWindow(runtime,state,preview,smokeFile); MainWindow=window;
        if(preview is not null) { window.ShowInTaskbar=false; window.WindowStartupLocation=WindowStartupLocation.Manual; window.Left=-20000; window.Top=-20000; }
        window.Show();
        if (e.Args.Contains("--show-continuous") && preview is null)
            new ContinuousWindow(state, runtime, path => { window.NavScan.IsChecked = true; window.TargetPath.Text = path; }) { Owner = window }.Show();
    }
}
