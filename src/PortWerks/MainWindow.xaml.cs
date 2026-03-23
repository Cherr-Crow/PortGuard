using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using PortWerks.Core.Export;
using PortWerks.Core.Interfaces;
using PortWerks.Core.Models;
using PortWerks.Core.Scanners;

namespace PortWerks
{
    public partial class MainWindow : Window
    {
        private CancellationTokenSource? _scanCancellation;
        private ScanResult? _currentResult;

        public MainWindow()
        {
            InitializeComponent();
            LogConsole("Port Werks initialized. Ready for scanning operations.");
            LogConsole("WARNING: This tool is for authorized security testing only.");
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(TargetTextBox.Text))
            {
                MessageBox.Show("Please enter a target host.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var ports = ParsePorts(PortsTextBox.Text);
            if (ports.Count == 0)
            {
                MessageBox.Show("Please enter valid ports.", "Invalid Input", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Prepare UI
            ScanButton.IsEnabled = false;
            StopButton.IsEnabled = true;
            ResultsDataGrid.ItemsSource = null;
            SetStatus("SCANNING", Colors.Yellow);

            _scanCancellation = new CancellationTokenSource();

            var config = new ScanConfiguration
            {
                TargetHost = TargetTextBox.Text.Trim(),
                Ports = ports,
                Technique = GetSelectedScanTechnique(),
     
                EnableServiceDetection = ServiceDetectionCheck.IsChecked == true,
                EnableOsFingerprinting = OsFingerprintCheck.IsChecked == true,
                EnableVersionDetection = VersionDetectionCheck.IsChecked == true
            };

            LogConsole($"Starting {config.Technique} scan of {config.TargetHost}");
            LogConsole($"Target ports: {ports.Count} ports");
            LogConsole($"Concurrency: {config.MaxConcurrentScans} threads");

            try
            {
                IScanner scanner = config.Technique switch
                {
                    ScanTechnique.SynScan => new SynScanner(),
                    ScanTechnique.UdpScan => new UdpScanner(),
                    _ => new TcpConnectScanner()
                };

                var progress = new Progress<ScanProgress>(p =>
                {
                    PortsScannedText.Text = $"{p.PortsScanned} / {p.TotalPorts}";
                    OpenPortsText.Text = p.OpenPortsFound.ToString();
                    ScanProgressBar.Value = p.PercentComplete;
                    ProgressText.Text = $"{p.PercentComplete:F1}%";
                    ScanSpeedText.Text = $"{p.PortsPerSecond:F0} p/s";

                    // Only log every 10% progress to reduce console flooding
                    if (!string.IsNullOrEmpty(p.CurrentPort) && (int)p.PercentComplete % 10 == 0)
                    {
                        LogConsole($"Progress: {p.PercentComplete:F0}% - {p.PortsScanned}/{p.TotalPorts} ports scanned, {p.OpenPortsFound} open");
                    }
                });

                _currentResult = await scanner.ScanAsync(config, progress, _scanCancellation.Token);

                // Update results
                ResultsDataGrid.ItemsSource = _currentResult.PortResults;
                ClosedPortsText.Text = _currentResult.Statistics.ClosedPorts.ToString();
                FilteredPortsText.Text = _currentResult.Statistics.FilteredPorts.ToString();

                // OS Detection if enabled
                if (config.EnableOsFingerprinting)
                {
                    LogConsole("Performing OS fingerprinting...");
                    var osDetector = new OsFingerprinter();
                    _currentResult.OperatingSystem = await osDetector.DetectOperatingSystemAsync(config.TargetHost);
                    LogConsole($"OS Detection: {_currentResult.OperatingSystem}");
                }

                LogConsole($"Scan complete! Duration: {_currentResult.Duration.TotalSeconds:F2}s");
                LogConsole($"Results: {_currentResult.Statistics.OpenPorts} open, " +
                          $"{_currentResult.Statistics.ClosedPorts} closed, " +
                          $"{_currentResult.Statistics.FilteredPorts} filtered");

                SetStatus("COMPLETE", Colors.Green);
            }
            catch (UnauthorizedAccessException ex)
            {
                LogConsole($"ERROR: {ex.Message}");
                MessageBox.Show(ex.Message, "Authorization Error", MessageBoxButton.OK, MessageBoxImage.Error);
                SetStatus("ERROR", Colors.Red);
            }
            catch (OperationCanceledException)
            {
                LogConsole("Scan cancelled by user.");
                SetStatus("CANCELLED", Colors.Orange);
            }
            catch (Exception ex)
            {
                LogConsole($"ERROR: {ex.Message}");
                MessageBox.Show($"Scan error: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                SetStatus("ERROR", Colors.Red);
            }
            finally
            {
                ScanButton.IsEnabled = true;
                StopButton.IsEnabled = false;
                _scanCancellation?.Dispose();
                _scanCancellation = null;

                if (StatusText.Text == "SCANNING")
                {
                    SetStatus("READY", Colors.Green);
                }
            }
        }

        private void StopButton_Click(object sender, RoutedEventArgs e)
        {
            _scanCancellation?.Cancel();
            LogConsole("Cancelling scan... Please wait.");
            SetStatus("CANCELLING", Colors.Orange);
            StopButton.IsEnabled = false; // Prevent multiple clicks
        }



        private async void ExportJson_Click(object sender, RoutedEventArgs e)
        {
            await ExportResultsAsync(new JsonExporter());
        }

        private async void ExportXml_Click(object sender, RoutedEventArgs e)
        {
            await ExportResultsAsync(new XmlExporter());
        }

        private async void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            await ExportResultsAsync(new CsvExporter());
        }

        private async void ExportHtml_Click(object sender, RoutedEventArgs e)
        {
            await ExportResultsAsync(new HtmlExporter());
        }

        private async Task ExportResultsAsync(IExporter exporter)
        {
            if (_currentResult == null)
            {
                MessageBox.Show("No scan results to export.", "No Data", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var dialog = new SaveFileDialog
            {
                Filter = $"{exporter.GetType().Name}|*{exporter.FileExtension}",
                FileName = $"portscan_{_currentResult.TargetHost}_{DateTime.Now:yyyyMMdd_HHmmss}{exporter.FileExtension}"
            };

            if (dialog.ShowDialog() == true)
            {
                try
                {
                    var content = await exporter.ExportAsync(_currentResult);
                    await File.WriteAllTextAsync(dialog.FileName, content);
                    LogConsole($"Results exported to {dialog.FileName}");
                    MessageBox.Show($"Results exported successfully!", "Export Complete", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    LogConsole($"Export error: {ex.Message}");
                    MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private List<int> ParsePorts(string input)
        {
            var ports = new List<int>();

            try
            {
                foreach (var part in input.Split(','))
                {
                    var trimmed = part.Trim();

                    if (trimmed.Contains('-'))
                    {
                        // Range
                        var range = trimmed.Split('-');
                        if (range.Length == 2 &&
                            int.TryParse(range[0].Trim(), out int start) &&
                            int.TryParse(range[1].Trim(), out int end))
                        {
                            for (int i = start; i <= end && i <= 65535; i++)
                            {
                                if (i > 0) ports.Add(i);
                            }
                        }
                    }
                    else if (int.TryParse(trimmed, out int port) && port > 0 && port <= 65535)
                    {
                        ports.Add(port);
                    }
                }
            }
            catch
            {
                // Invalid format
            }

            return ports.Distinct().OrderBy(p => p).ToList();
        }

        private ScanTechnique GetSelectedScanTechnique()
        {
            return ScanTechniqueCombo.SelectedIndex switch
            {
                1 => ScanTechnique.SynScan,
                2 => ScanTechnique.UdpScan,
                _ => ScanTechnique.TcpConnect
            };
        }



        private void SetStatus(string status, Color color)
        {
            StatusText.Text = status;
            StatusText.Foreground = new SolidColorBrush(color);
            StatusLED.Fill = new SolidColorBrush(color);
        }

        private void LogConsole(string message)
        {
            var timestamp = DateTime.Now.ToString("HH:mm:ss");
            ConsoleOutput.Text += $"[{timestamp}] {message}\n";

            // Auto-scroll
            if (ConsoleOutput.Parent is ScrollViewer scrollViewer)
            {
                scrollViewer.ScrollToEnd();
            }
        }

        private void ResultsDataGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

        }

        private void ScanTechniqueCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

        }

        private void TargetTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }
    }
}
