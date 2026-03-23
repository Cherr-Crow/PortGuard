using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using PortWerks.Core.Interfaces;
using PortWerks.Core.Models;

namespace PortWerks.Core.Scanners
{
    public class TcpConnectScanner : IScanner
    {
        private readonly ServiceDetector _serviceDetector;

        public TcpConnectScanner()
        {
            _serviceDetector = new ServiceDetector();
        }

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

            // Rate limiting semaphore
            using var rateLimiter = config.RateLimitPerSecond > 0
                ? new SemaphoreSlim(config.RateLimitPerSecond)
                : null;

            // Concurrent scanning with semaphore for max parallel operations
            using var semaphore = new SemaphoreSlim(config.MaxConcurrentScans);

            var tasks = config.Ports.Select(async port =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    if (rateLimiter != null)
                    {
                        await rateLimiter.WaitAsync(cancellationToken);
                        _ = Task.Run(async () =>
                        {
                            await Task.Delay(1000, cancellationToken);
                            rateLimiter.Release();
                        }, cancellationToken);
                    }

                    var portResult = await ScanPortAsync(config.TargetHost, port, config.TimeoutMs, config.EnableServiceDetection, cancellationToken);
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

        private async Task<PortResult> ScanPortAsync(string host, int port, int timeoutMs, bool detectService, CancellationToken cancellationToken)
        {
            var result = new PortResult
            {
                Port = port,
                Protocol = Protocol.TCP
            };

            var stopwatch = Stopwatch.StartNew();

            try
            {
                using var client = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(timeoutMs);

                await client.ConnectAsync(host, port, cts.Token);

                result.State = PortState.Open;
                result.ResponseTime = stopwatch.Elapsed;

                if (detectService && client.Connected)
                {
                    var serviceInfo = await _serviceDetector.DetectServiceAsync(client, port, cancellationToken);
                    result.ServiceName = serviceInfo.ServiceName;
                    result.ServiceVersion = serviceInfo.Version;
                    result.Banner = serviceInfo.Banner;
                    result.VulnerabilityHints = serviceInfo.VulnerabilityHints;
                }
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
            catch
            {
                result.State = PortState.Unknown;
            }

            stopwatch.Stop();
            return result;
        }
    }
}
