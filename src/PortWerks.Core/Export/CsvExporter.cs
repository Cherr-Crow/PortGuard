using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PortWerks.Core.Models;

namespace PortWerks.Core.Export
{
    public class CsvExporter : IExporter
    {
        public string FileExtension => ".csv";

        public Task<string> ExportAsync(ScanResult result)
        {
            var sb = new StringBuilder();

            // Header
            sb.AppendLine("Port,State,Protocol,Service,Version,Response Time (ms),Banner,Vulnerability Hints");

            // Data rows
            foreach (var port in result.PortResults)
            {
                sb.AppendLine($"{port.Port}," +
                    $"{port.State}," +
                    $"{port.Protocol}," +
                    $"\"{port.ServiceName ?? ""}\"," +
                    $"\"{port.ServiceVersion ?? ""}\"," +
                    $"{port.ResponseTime.TotalMilliseconds:F2}," +
                    $"\"{EscapeCsv(port.Banner)}\"," +
                    $"\"{EscapeCsv(string.Join("; ", port.VulnerabilityHints))}\"");
            }

            return Task.FromResult(sb.ToString());
        }

        private string EscapeCsv(string? value)
        {
            if (string.IsNullOrEmpty(value)) return string.Empty;
            return value.Replace("\"", "\"\"").Replace("\n", " ").Replace("\r", "");
        }
    }
}
