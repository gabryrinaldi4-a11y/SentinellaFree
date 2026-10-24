using System.IO;
using System.Text.Json;
using System.Windows;
namespace Sentinella.Desktop;
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
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
        var window = new MainWindow(runtime,state,preview,smokeFile); MainWindow=window;
        if(preview is not null) { window.ShowInTaskbar=false; window.WindowStartupLocation=WindowStartupLocation.Manual; window.Left=-20000; window.Top=-20000; }
        window.Show();
    }
}


