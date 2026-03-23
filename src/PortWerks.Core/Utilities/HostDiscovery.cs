using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace PortWerks.Core.Utilities
{
    /// <summary>
    /// Host discovery using ping sweeps
    /// </summary>
    public class HostDiscovery
    {
        public async Task<List<string>> PingSweepAsync(string subnet, int timeout = 1000)
        {
            var activeHosts = new List<string>();
            var tasks = new List<Task<(string host, bool isAlive)>>();

            // Parse subnet (e.g., "192.168.1.0/24")
            var hosts = ParseSubnet(subnet);

            foreach (var host in hosts)
            {
                tasks.Add(PingHostAsync(host, timeout));
            }

            var results = await Task.WhenAll(tasks);

            return results
                .Where(r => r.isAlive)
                .Select(r => r.host)
                .ToList();
        }

        private async Task<(string host, bool isAlive)> PingHostAsync(string host, int timeout)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(host, timeout);
                return (host, reply.Status == IPStatus.Success);
            }
            catch
            {
                return (host, false);
            }
        }

        private List<string> ParseSubnet(string subnet)
        {
            var hosts = new List<string>();

            // Simple implementation for /24 networks
            // Full implementation would support CIDR notation properly
            if (subnet.EndsWith("/24"))
            {
                var baseIp = subnet.Replace("/24", "");
                var parts = baseIp.Split('.');

                if (parts.Length == 4)
                {
                    for (int i = 1; i < 255; i++)
                    {
                        hosts.Add($"{parts[0]}.{parts[1]}.{parts[2]}.{i}");
                    }
                }
            }
            else if (subnet.Contains("-"))
            {
                // Range notation: 192.168.1.1-192.168.1.50
                var rangeParts = subnet.Split('-');
                if (rangeParts.Length == 2)
                {
                    var start = IPAddress.Parse(rangeParts[0].Trim());
                    var end = IPAddress.Parse(rangeParts[1].Trim());

                    var startBytes = start.GetAddressBytes();
                    var endBytes = end.GetAddressBytes();

                    for (byte i = startBytes[3]; i <= endBytes[3]; i++)
                    {
                        hosts.Add($"{startBytes[0]}.{startBytes[1]}.{startBytes[2]}.{i}");
                    }
                }
            }
            else
            {
                // Single host
                hosts.Add(subnet);
            }

            return hosts;
        }
    }
}
