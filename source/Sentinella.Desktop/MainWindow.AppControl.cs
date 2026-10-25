using System.Windows;
namespace Sentinella.Desktop;
public partial class MainWindow
{
    void OpenAppControl(object sender, RoutedEventArgs e)
    {
        try { new AppControlWindow(stateRoot, runtimeRoot) { Owner = this }.ShowDialog(); }
        catch (Exception ex) { MessageBox.Show(this, ex.Message, "Controllo applicazioni non disponibile", MessageBoxButton.OK, MessageBoxImage.Error); }
    }
}
