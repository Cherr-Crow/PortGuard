using System.Collections.Generic;

namespace PortWerks.Core.Models
{
    public class ScanConfiguration
    {
        public string TargetHost { get; set; } = string.Empty;
        public List<int> Ports { get; set; } = new();
        public ScanTechnique Technique { get; set; } = ScanTechnique.TcpConnect;
        public int MaxConcurrentScans { get; set; } = 100;
        public int TimeoutMs { get; set; } = 2000;
        public bool EnableServiceDetection { get; set; } = true;
        public bool EnableOsFingerprinting { get; set; } = false;
        public bool EnableVersionDetection { get; set; } = true;
        public int RateLimitPerSecond { get; set; } = 0; // 0 = no limit
        public EvasionOptions Evasion { get; set; } = new();
    }

    public enum ScanTechnique
    {
        TcpConnect,
        SynScan,
        UdpScan,
        TcpAck,
        TcpWindow
    }

    public class EvasionOptions
    {
        public bool UseFragmentation { get; set; } = false;
        public bool RandomizeSourcePort { get; set; } = false;
        public int TimingTemplate { get; set; } = 3; // 0=paranoid, 5=insane
        public List<string> DecoyAddresses { get; set; } = new();
    }

    public static class CommonPorts
    {
        public static readonly int[] Top20 = new[]
        {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
        };

        public static readonly int[] Top100 = new[]
        {
            7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
            139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
            554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
            1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
            4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
            6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
            49152, 49153, 49154, 49155, 49156, 49157
        };
    }
}
