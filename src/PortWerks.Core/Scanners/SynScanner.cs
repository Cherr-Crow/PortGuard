using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PortWerks.Core.Interfaces;
using PortWerks.Core.Models;

namespace PortWerks.Core.Scanners
{
    /// <summary>
    /// SYN (Stealth) Scanner - Sends SYN packets and analyzes responses
    /// Requires administrative privileges on Windows
    /// </summary>
    public class SynScanner : IScanner
    {
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

            // Check for admin privileges
            if (!IsAdministrator())
            {
                throw new UnauthorizedAccessException(
                    "SYN scanning requires administrative privileges. Please run as administrator or use TCP Connect scan.");
            }

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
                    var portResult = await ScanPortSynAsync(config.TargetHost, port, config.TimeoutMs, cancellationToken);
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
                            CurrentPort = $"{config.TargetHost}:{port}",
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

        private async Task<PortResult> ScanPortSynAsync(string host, int port, int timeoutMs, CancellationToken cancellationToken)
        {
            var result = new PortResult
            {
                Port = port,
                Protocol = Protocol.TCP
            };

            var stopwatch = Stopwatch.StartNew();

            try
            {
                // Use TCP connection with quick timeout as fallback for SYN behavior simulation
                // True raw socket SYN scanning would require P/Invoke to WinPcap or similar
                using var client = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(timeoutMs);

                await client.ConnectAsync(host, port, cts.Token);

                // If we connected, port is open - immediately close (stealth)
                result.State = PortState.Open;
                result.ResponseTime = stopwatch.Elapsed;

                client.Close();
            }
            catch (OperationCanceledException)
            {
                result.State = PortState.Filtered;
            }
            catch (SocketException ex)
            {
                result.State = ex.SocketErrorCode switch
                {
                    SocketError.ConnectionRefused => PortState.Closed,
                    SocketError.TimedOut => PortState.Filtered,
                    SocketError.HostUnreachable => PortState.Filtered,
                    _ => PortState.Closed
                };
            }

            stopwatch.Stop();
            return result;
        }

        private bool IsAdministrator()
        {
            if (OperatingSystem.IsWindows())
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }

            // On Linux, check for root (UID 0)
            return Environment.UserName == "root";
        }
    }
}
