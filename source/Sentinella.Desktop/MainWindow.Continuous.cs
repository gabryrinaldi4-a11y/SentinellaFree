using System.Windows;
namespace Sentinella.Desktop;
public partial class MainWindow
{
    void OpenContinuous(object sender, RoutedEventArgs e)
    {
        try { new ContinuousWindow(stateRoot, runtimeRoot, path => { NavScan.IsChecked = true; TargetPath.Text = path; }) { Owner = this }.ShowDialog(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Monitor non disponibile", MessageBoxButton.OK, MessageBoxImage.Error); }
    }
}
