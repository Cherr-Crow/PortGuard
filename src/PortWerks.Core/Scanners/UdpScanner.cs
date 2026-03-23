using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using PortWerks.Core.Interfaces;
using PortWerks.Core.Models;

namespace PortWerks.Core.Scanners
{
    public class UdpScanner : IScanner
    {
        private static readonly Dictionary<int, byte[]> UdpProbes = new()
        {
            { 53, Encoding.ASCII.GetBytes("\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00") }, // DNS query
            { 161, Encoding.ASCII.GetBytes("\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63") }, // SNMP
            { 123, new byte[] { 0x1B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } // NTP
        };

        public async Task<ScanResult> ScanAsync(
            ScanConfiguration config,
            IProgress<ScanProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var result = new ScanResult
            {
                TargetHost = config.TargetHost,
                ScanStartTime = DateTime.Now
            };

            var portResults = new ConcurrentBag<PortResult>();
            var scannedCount = 0;
            var openCount = 0;
            var startTime = Stopwatch.StartNew();
            var lastProgressReport = DateTime.MinValue;
            var progressLock = new object();

            using var semaphore = new SemaphoreSlim(config.MaxConcurrentScans);

            var tasks = config.Ports.Select(async port =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    var portResult = await ScanPortUdpAsync(config.TargetHost, port, config.TimeoutMs, cancellationToken);
                    portResults.Add(portResult);

                    var scanned = Interlocked.Increment(ref scannedCount);
                    if (portResult.State == PortState.Open)
                    {
                        Interlocked.Increment(ref openCount);
                    }

                    // Throttle progress updates to prevent UI thread flooding
                    // Only report every 100ms or if it's the last port
                    var shouldReport = false;
                    lock (progressLock)
                    {
                        var now = DateTime.Now;
                        if ((now - lastProgressReport).TotalMilliseconds >= 100 || scanned == config.Ports.Count)
                        {
                            lastProgressReport = now;
                            shouldReport = true;
                        }
                    }

                    if (shouldReport && progress != null)
                    {
                        progress.Report(new ScanProgress
                        {
                            PortsScanned = scanned,
                            TotalPorts = config.Ports.Count,
                            OpenPortsFound = openCount,
                            CurrentPort = $"{config.TargetHost}:{port} (UDP)",
                            PortsPerSecond = scanned / startTime.Elapsed.TotalSeconds
                        });
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            }).ToArray();

            await Task.WhenAll(tasks);

            result.PortResults = portResults.OrderBy(p => p.Port).ToList();
            result.ScanEndTime = DateTime.Now;
            result.Statistics = new ScanStatistics
            {
                TotalPorts = config.Ports.Count,
                OpenPorts = result.PortResults.Count(p => p.State == PortState.Open),
                ClosedPorts = result.PortResults.Count(p => p.State == PortState.Closed),
                FilteredPorts = result.PortResults.Count(p => p.State == PortState.Filtered),
                PortsPerSecond = config.Ports.Count / result.Duration.TotalSeconds
            };

            return result;
        }

        private async Task<PortResult> ScanPortUdpAsync(string host, int port, int timeoutMs, CancellationToken cancellationToken)
        {
            var result = new PortResult
            {
                Port = port,
                Protocol = Protocol.UDP
            };

            var stopwatch = Stopwatch.StartNew();

            try
            {
                using var client = new UdpClient();
                client.Client.ReceiveTimeout = timeoutMs;
                client.Client.SendTimeout = timeoutMs;

                var endpoint = new IPEndPoint(IPAddress.Parse(host), port);
                client.Connect(endpoint);

                // Send probe data
                byte[] probe = UdpProbes.TryGetValue(port, out var customProbe)
                    ? customProbe
                    : Encoding.ASCII.GetBytes("PortWerks");

                await client.SendAsync(probe, probe.Length);

                // Try to receive response
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(timeoutMs);

                try
                {
                    var response = await client.ReceiveAsync(cts.Token);
                    result.State = PortState.Open;
                    result.ResponseTime = stopwatch.Elapsed;

                    if (response.Buffer.Length > 0)
                    {
                        result.Banner = Encoding.ASCII.GetString(response.Buffer).Trim();
                    }
                }
                catch (OperationCanceledException)
                {
                    // No response - could be open|filtered
                    result.State = PortState.OpenFiltered;
                }
            }
            catch (SocketException ex)
            {
                // ICMP Port Unreachable = Closed
                result.State = ex.SocketErrorCode == SocketError.ConnectionReset
                    ? PortState.Closed
                    : PortState.OpenFiltered;
            }
            catch
            {
                result.State = PortState.OpenFiltered;
            }

            stopwatch.Stop();
            return result;
        }
    }
}
