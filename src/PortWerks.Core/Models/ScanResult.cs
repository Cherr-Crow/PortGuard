using System;
using System.Collections.Generic;

namespace PortWerks.Core.Models
{
    public class ScanResult
    {
        public string TargetHost { get; set; } = string.Empty;
        public DateTime ScanStartTime { get; set; }
        public DateTime ScanEndTime { get; set; }
        public TimeSpan Duration => ScanEndTime - ScanStartTime;
        public List<PortResult> PortResults { get; set; } = new();
        public string? OperatingSystem { get; set; }
        public ScanStatistics Statistics { get; set; } = new();
    }

    public class PortResult
    {
        public int Port { get; set; }
        public PortState State { get; set; }
        public Protocol Protocol { get; set; }
        public string? ServiceName { get; set; }
        public string? ServiceVersion { get; set; }
        public string? Banner { get; set; }
        public TimeSpan ResponseTime { get; set; }
        public List<string> VulnerabilityHints { get; set; } = new();
    }

    public enum PortState
    {
        Open,
        Closed,
        Filtered,
        OpenFiltered,
        Unknown
    }

    public enum Protocol
    {
        TCP,
        UDP
    }

    public class ScanStatistics
    {
        public int TotalPorts { get; set; }
        public int OpenPorts { get; set; }
        public int ClosedPorts { get; set; }
        public int FilteredPorts { get; set; }
        public double PortsPerSecond { get; set; }
    }
}
