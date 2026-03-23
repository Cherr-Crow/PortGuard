using System;
using System.Threading;
using System.Threading.Tasks;
using PortWerks.Core.Models;

namespace PortWerks.Core.Interfaces
{
    public interface IScanner
    {
        Task<ScanResult> ScanAsync(ScanConfiguration config, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default);
    }

    public class ScanProgress
    {
        public int PortsScanned { get; set; }
        public int TotalPorts { get; set; }
        public int OpenPortsFound { get; set; }
        public double PercentComplete => TotalPorts > 0 ? (double)PortsScanned / TotalPorts * 100 : 0;
        public string CurrentPort { get; set; } = string.Empty;
        public double PortsPerSecond { get; set; }
    }
}
