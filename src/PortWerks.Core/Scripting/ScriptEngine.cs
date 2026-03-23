using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using PortWerks.Core.Models;

namespace PortWerks.Core.Scripting
{
    /// <summary>
    /// Script engine for running custom port checks
    /// Scripts can perform custom probes and analysis
    /// </summary>
    public class ScriptEngine
    {
        private readonly Dictionary<string, IPortScript> _scripts = new();

        public ScriptEngine()
        {
            // Register built-in scripts
            RegisterScript("http-headers", new HttpHeadersScript());
            RegisterScript("ssl-info", new SslInfoScript());
            RegisterScript("smtp-commands", new SmtpCommandsScript());
        }

        public void RegisterScript(string name, IPortScript script)
        {
            _scripts[name] = script;
        }

        public async Task<ScriptResult> ExecuteScriptAsync(string scriptName, string host, int port)
        {
            if (!_scripts.TryGetValue(scriptName, out var script))
            {
                return new ScriptResult
                {
                    Success = false,
                    Error = $"Script '{scriptName}' not found"
                };
            }

            try
            {
                return await script.ExecuteAsync(host, port);
            }
            catch (Exception ex)
            {
                return new ScriptResult
                {
                    Success = false,
                    Error = ex.Message
                };
            }
        }

        public IEnumerable<string> GetAvailableScripts() => _scripts.Keys;
    }

    public interface IPortScript
    {
        Task<ScriptResult> ExecuteAsync(string host, int port);
    }

    public class ScriptResult
    {
        public bool Success { get; set; }
        public string? Error { get; set; }
        public Dictionary<string, string> Data { get; set; } = new();
        public List<string> Findings { get; set; } = new();
    }

    // Built-in Scripts

    public class HttpHeadersScript : IPortScript
    {
        public async Task<ScriptResult> ExecuteAsync(string host, int port)
        {
            var result = new ScriptResult { Success = true };

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port);

                using var stream = client.GetStream();
                var request = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n");
                await stream.WriteAsync(request, 0, request.Length);

                var buffer = new byte[4096];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                var response = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                // Parse headers
                var lines = response.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    if (line.Contains(':'))
                    {
                        var parts = line.Split(new[] { ':' }, 2);
                        result.Data[parts[0].Trim()] = parts[1].Trim();
                    }
                }

                // Security checks
                if (!result.Data.ContainsKey("X-Frame-Options"))
                    result.Findings.Add("Missing X-Frame-Options header (clickjacking risk)");

                if (!result.Data.ContainsKey("X-Content-Type-Options"))
                    result.Findings.Add("Missing X-Content-Type-Options header");

                if (!result.Data.ContainsKey("Strict-Transport-Security"))
                    result.Findings.Add("Missing HSTS header (not enforcing HTTPS)");

                if (result.Data.ContainsKey("Server"))
                    result.Findings.Add($"Server version disclosure: {result.Data["Server"]}");
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
            }

            return result;
        }
    }

    public class SslInfoScript : IPortScript
    {
        public async Task<ScriptResult> ExecuteAsync(string host, int port)
        {
            var result = new ScriptResult { Success = true };

            // Note: Full SSL/TLS analysis would require additional libraries
            // This is a simplified version
            result.Data["Note"] = "SSL/TLS analysis requires extended implementation";
            result.Findings.Add("Recommend using tools like SSLScan or TestSSL for comprehensive SSL analysis");

            await Task.CompletedTask;
            return result;
        }
    }

    public class SmtpCommandsScript : IPortScript
    {
        public async Task<ScriptResult> ExecuteAsync(string host, int port)
        {
            var result = new ScriptResult { Success = true };

            try
            {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port);

                using var stream = client.GetStream();
                var buffer = new byte[1024];

                // Read banner
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                var banner = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                result.Data["Banner"] = banner;

                // Try VRFY command (username enumeration)
                var vrfyCmd = Encoding.ASCII.GetBytes("VRFY root\r\n");
                await stream.WriteAsync(vrfyCmd, 0, vrfyCmd.Length);
                bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                var vrfyResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                if (!vrfyResponse.StartsWith("252"))
                {
                    result.Findings.Add("VRFY command may be enabled (username enumeration risk)");
                }

                // Try EXPN command
                var expnCmd = Encoding.ASCII.GetBytes("EXPN root\r\n");
                await stream.WriteAsync(expnCmd, 0, expnCmd.Length);
                bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                var expnResponse = Encoding.ASCII.GetString(buffer, 0, bytesRead);

                if (!expnResponse.StartsWith("252"))
                {
                    result.Findings.Add("EXPN command may be enabled (mailing list disclosure risk)");
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Error = ex.Message;
            }

            return result;
        }
    }
}
