using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PortWerks.Core.Scanners
{
    public class ServiceDetector
    {
        private static readonly Dictionary<int, string> CommonServices = new()
        {
            { 20, "ftp-data" }, { 21, "ftp" }, { 22, "ssh" }, { 23, "telnet" },
            { 25, "smtp" }, { 53, "dns" }, { 80, "http" }, { 110, "pop3" },
            { 143, "imap" }, { 443, "https" }, { 445, "smb" }, { 3306, "mysql" },
            { 3389, "rdp" }, { 5432, "postgresql" }, { 5900, "vnc" }, { 6379, "redis" },
            { 8080, "http-proxy" }, { 27017, "mongodb" }
        };

        private static readonly Dictionary<string, List<string>> VulnerabilityDatabase = new()
        {
            { "ftp", new List<string> { "Check for anonymous login", "Verify FTP version for known CVEs" } },
            { "ssh", new List<string> { "Check for weak key exchange algorithms", "Test for username enumeration" } },
            { "telnet", new List<string> { "CRITICAL: Unencrypted protocol", "Consider replacing with SSH" } },
            { "smtp", new List<string> { "Test for open relay", "Check for user enumeration via VRFY/EXPN" } },
            { "http", new List<string> { "Check for default credentials", "Test for common vulnerabilities (SQLi, XSS)" } },
            { "https", new List<string> { "Check SSL/TLS configuration", "Verify certificate validity" } },
            { "smb", new List<string> { "Check for EternalBlue (MS17-010)", "Test for null session authentication" } },
            { "mysql", new List<string> { "Test for default credentials", "Check for information disclosure" } },
            { "rdp", new List<string> { "Check for BlueKeep (CVE-2019-0708)", "Test for weak credentials" } },
            { "vnc", new List<string> { "Test for weak/no authentication", "Check VNC version" } },
            { "redis", new List<string> { "Test for unauthenticated access", "Check for command injection" } }
        };

        public async Task<ServiceInfo> DetectServiceAsync(TcpClient client, int port, CancellationToken cancellationToken)
        {
            var serviceInfo = new ServiceInfo
            {
                ServiceName = CommonServices.TryGetValue(port, out var serviceName) ? serviceName : "unknown"
            };

            try
            {
                if (!client.Connected) return serviceInfo;

                var stream = client.GetStream();
                stream.ReadTimeout = 2000;
                stream.WriteTimeout = 2000;

                // Try to grab banner
                var banner = await TryGetBannerAsync(stream, cancellationToken);
                if (!string.IsNullOrWhiteSpace(banner))
                {
                    serviceInfo.Banner = banner;
                    serviceInfo.Version = ExtractVersion(banner);
                }

                // Get vulnerability hints
                if (VulnerabilityDatabase.TryGetValue(serviceInfo.ServiceName, out var hints))
                {
                    serviceInfo.VulnerabilityHints = new List<string>(hints);
                }
            }
            catch
            {
                // Silent fail - service detection is best effort
            }

            return serviceInfo;
        }

        private async Task<string?> TryGetBannerAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            try
            {
                var buffer = new byte[4096];
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(1000);

                // Some services send banner immediately
                if (stream.DataAvailable)
                {
                    var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                    return Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
                }

                // For HTTP, send a request
                var request = Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\n\r\n");
                await stream.WriteAsync(request, 0, request.Length, cts.Token);
                await stream.FlushAsync(cts.Token);

                var bytesRead2 = await stream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                if (bytesRead2 > 0)
                {
                    return Encoding.ASCII.GetString(buffer, 0, bytesRead2).Trim();
                }
            }
            catch
            {
                // Silent fail
            }

            return null;
        }

        private string? ExtractVersion(string banner)
        {
            // Simple version extraction - looks for common patterns
            var patterns = new[] { @"(\d+\.\d+\.\d+)", @"(\d+\.\d+)" };

            foreach (var pattern in patterns)
            {
                var match = System.Text.RegularExpressions.Regex.Match(banner, pattern);
                if (match.Success)
                {
                    return match.Groups[1].Value;
                }
            }

            return null;
        }
    }

    public class ServiceInfo
    {
        public string ServiceName { get; set; } = "unknown";
        public string? Version { get; set; }
        public string? Banner { get; set; }
        public List<string> VulnerabilityHints { get; set; } = new();
    }
}
