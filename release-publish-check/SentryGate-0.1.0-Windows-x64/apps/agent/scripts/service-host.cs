using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.ServiceProcess;
using System.Text;
using System.Threading;

internal sealed class SentryGateAgentService : ServiceBase
{
    private readonly string node, entry, config, ca;
    private Process child;
    private volatile bool stopping;
    private Thread worker;
    private readonly string logPath;

    private SentryGateAgentService(string[] args)
    {
        ServiceName = "SentryGateAgent";
        CanStop = true;
        CanShutdown = true;
        node = args[0]; entry = args[1]; config = args[2]; ca = args.Length > 3 ? args[3] : "";
        logPath = Path.Combine(Path.GetDirectoryName(config), "logs", "service.log");
    }

    protected override void OnStart(string[] args)
    {
        stopping = false;
        worker = new Thread(Run) { IsBackground = true, Name = "SentryGate agent supervisor" };
        worker.Start();
    }

    protected override void OnStop() { StopAgent(); }
    protected override void OnShutdown() { StopAgent(); }

    private void StopAgent()
    {
        stopping = true;
        try { if (child != null && !child.HasExited) child.Kill(); } catch (Exception ex) { Log("Agent stop error: " + ex.Message); }
        try { if (worker != null && worker.IsAlive) worker.Join(10000); } catch { }
        Log("Service stopped.");
    }

    private void Run()
    {
        Log("Service started; waiting for local backend health before starting the agent.");
        while (!stopping)
        {
            try
            {
                string api = ReadApiUrl();
                if (!BackendReady(api)) { Log("Local backend is not ready; retrying in 5 seconds."); Thread.Sleep(5000); continue; }
                Log("Local backend is ready; starting the monitoring agent.");
                var start = new ProcessStartInfo { FileName = node, Arguments = Quote(entry) + " " + Quote(config) + (String.IsNullOrEmpty(ca) ? "" : " " + Quote(ca)), WorkingDirectory = Path.GetDirectoryName(entry), UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                child = new Process { StartInfo = start, EnableRaisingEvents = true };
                child.OutputDataReceived += (s, e) => { if (e.Data != null) Log("agent: " + e.Data); };
                child.ErrorDataReceived += (s, e) => { if (e.Data != null) Log("agent error: " + e.Data); };
                if (!child.Start()) throw new InvalidOperationException("Could not start agent process.");
                child.BeginOutputReadLine(); child.BeginErrorReadLine();
                child.WaitForExit();
                int code = child.ExitCode;
                child.Dispose(); child = null;
                if (stopping) break;
                Log("Agent process exited with code " + code + "; service will exit for SCM recovery.");
                Environment.Exit(code == 0 ? 1 : code);
            }
            catch (Exception ex) { Log("Service startup or collector supervisor error: " + ex.Message); Thread.Sleep(5000); }
        }
    }

    private string ReadApiUrl()
    {
        string text = File.ReadAllText(config, Encoding.UTF8);
        var match = System.Text.RegularExpressions.Regex.Match(text, "\"apiBaseUrl\"\\s*:\\s*\"([^\"]+)\"");
        if (!match.Success) throw new InvalidDataException("Agent configuration has no API URL.");
        return match.Groups[1].Value;
    }

    private bool BackendReady(string api)
    {
        Uri uri = new Uri(api.TrimEnd('/') + "/api/health");
        if (uri.Scheme != "http" || !(uri.Host == "127.0.0.1" || uri.Host == "localhost" || uri.Host == "[::1]" || uri.Host == "::1")) throw new InvalidOperationException("Windows service backend must be local loopback HTTP or verified local HTTPS.");
        try
        {
            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.Timeout = 2500; request.ReadWriteTimeout = 2500; request.Proxy = null;
            using (var response = (HttpWebResponse)request.GetResponse())
            using (var reader = new StreamReader(response.GetResponseStream()))
            {
                string body = reader.ReadToEnd();
                return (int)response.StatusCode >= 200 && (int)response.StatusCode < 300 && body.Contains("\"ok\":true") && body.Contains("\"database\":\"ready\"");
            }
        }
        catch (WebException) { return false; }
    }

    private void Log(string message)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(logPath));
            string safe = System.Text.RegularExpressions.Regex.Replace(message ?? "", "(?i)(authorization|bearer|credential|password|token)(\\s*[:= ]\\s*)[^ ,;\"]+", "$1$2[REDACTED]");
            if (File.Exists(logPath) && new FileInfo(logPath).Length > 2 * 1024 * 1024)
            {
                for (int i = 3; i >= 1; i--) { string from = logPath + "." + i, to = logPath + "." + (i + 1); if (File.Exists(from)) { if (i == 3) File.Delete(from); File.Move(from, to); } }
                if (File.Exists(logPath + ".1")) File.Delete(logPath + ".1");
                File.Move(logPath, logPath + ".1");
            }
            File.AppendAllText(logPath, DateTime.UtcNow.ToString("o") + " " + safe + Environment.NewLine, Encoding.UTF8);
        }
        catch { /* Logging failures must not stop local monitoring. */ }
    }

    private static string Quote(string value) { return "\"" + (value ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\""; }
    public static void Main(string[] args) { if (args.Length < 3) Environment.Exit(2); ServiceBase.Run(new SentryGateAgentService(args)); }
}
