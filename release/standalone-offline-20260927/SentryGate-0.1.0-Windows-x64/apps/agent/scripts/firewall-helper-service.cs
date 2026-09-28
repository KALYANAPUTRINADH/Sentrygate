using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

internal sealed class FirewallHelperService : ServiceBase
{
    private const string PipeName = "SentryGate.Firewall";
    private volatile bool stopping;
    private Thread worker;
    private Thread expiryWorker;
    private readonly ManualResetEvent stopSignal = new ManualResetEvent(false);
    private readonly object firewallLock = new object();
    private readonly JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = 2 * 1024 * 1024 };

    public FirewallHelperService() { ServiceName = "SentryGateFirewallHelper"; CanStop = true; }

    protected override void OnStart(string[] args)
    {
        worker = new Thread(PipeLoop) { IsBackground = true };
        worker.Start();
        expiryWorker = new Thread(ExpiryLoop) { IsBackground = true };
        expiryWorker.Start();
    }

    protected override void OnStop()
    {
        stopping = true;
        stopSignal.Set();
        try { worker.Join(5000); } catch { }
        try { expiryWorker.Join(5000); } catch { }
    }

    private void PipeLoop()
    {
        while (!stopping)
        {
            try
            {
                var security = new PipeSecurity();
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier("NT SERVICE\\SentryGateAgent"), PipeAccessRights.ReadWrite, AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
                using (var pipe = new NamedPipeServerStream(PipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None, 65536, 65536, security))
                {
                    pipe.WaitForConnection();
                    if (stopping) break;
                    using (var input = new StreamReader(pipe, Encoding.UTF8, false, 4096, true))
                    using (var output = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true })
                    {
                        string request = input.ReadLine();
                        string response;
                        try { lock (firewallLock) response = ProcessRequest(request); }
                        catch { response = "{\"error\":\"Firewall helper rejected the authenticated request.\"}"; }
                        output.WriteLine(response);
                    }
                }
            }
            catch { if (!stopping) Thread.Sleep(250); }
        }
    }

    private void ExpiryLoop()
    {
        while (!stopSignal.WaitOne(TimeSpan.FromSeconds(30)))
        {
            try { lock (firewallLock) RunFirewallScript("{\"action\":\"pruneExpired\"}"); }
            catch { }
        }
    }

    private string ProcessRequest(string request)
    {
        if (String.IsNullOrEmpty(request) || request.Length > 1024 * 1024) throw new InvalidDataException();
        var envelope = serializer.Deserialize<Dictionary<string, object>>(request);
        string encoded = Convert.ToString(envelope["payload"]), signature = Convert.ToString(envelope["signature"]);
        byte[] payload = Convert.FromBase64String(encoded), supplied = Convert.FromBase64String(signature);
        byte[] key = ReadMachineKey();
        byte[] expected;
        using (var hmac = new HMACSHA256(key)) expected = hmac.ComputeHash(payload);
        if (!FixedEquals(expected, supplied)) throw new UnauthorizedAccessException();
        var body = serializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(payload));
        var issued = DateTimeOffset.Parse(Convert.ToString(body["issuedAt"])).ToUniversalTime();
        var expires = DateTimeOffset.Parse(Convert.ToString(body["expiresAt"])).ToUniversalTime();
        string nonce = Convert.ToString(body["nonce"]);
        var now = DateTimeOffset.UtcNow;
        Guid parsedNonce;
        if (issued < now.AddMinutes(-2) || issued > now.AddSeconds(15) || expires <= now || expires > issued.AddMinutes(2) || !Guid.TryParse(nonce, out parsedNonce)) throw new UnauthorizedAccessException("Expired command.");
        ConsumeNonce(nonce, now);
        var rules = body["rules"] as System.Collections.ArrayList;
        if (rules == null || rules.Count > 100) throw new InvalidDataException();
        foreach (var item in rules) ValidateRule(item as Dictionary<string, object>, now);
        return RunFirewallScript(serializer.Serialize(new { rules = rules }));
    }

    private string RunFirewallScript(string inputJson)
    {
        var script = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "scripts", "firewall.ps1");
        var start = new ProcessStartInfo { FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
            Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + script + "\"", UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using (var child = Process.Start(start))
        {
            var stdout = new StringBuilder();
            child.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null && stdout.Length < 1048576) stdout.AppendLine(e.Data); };
            child.ErrorDataReceived += delegate { };
            child.BeginOutputReadLine(); child.BeginErrorReadLine();
            child.StandardInput.Write(inputJson); child.StandardInput.Close();
            bool exited = child.WaitForExit(30000);
            if (!exited) { try { child.Kill(); } catch { } throw new System.TimeoutException(); }
            child.WaitForExit();
            if (child.ExitCode != 0 || stdout.Length > 1024 * 1024) throw new InvalidOperationException();
            return stdout.ToString().Trim();
        }
    }

    private void ValidateRule(Dictionary<string, object> rule, DateTimeOffset now)
    {
        if (rule == null) throw new InvalidDataException();
        string id = Convert.ToString(rule["id"]), name = Convert.ToString(rule["name"]), group = Convert.ToString(rule["group"]);
        string kind = Convert.ToString(rule.ContainsKey("kind") ? rule["kind"] : "inbound");
        string operation = Convert.ToString(rule["operation"]);
        Guid parsedId;
        if (!Guid.TryParse(id, out parsedId) || group != "SentryGate" || name != (kind == "application" ? "SentryGate-App-" : "SentryGate-") + id || (operation != "ensure" && operation != "remove")) throw new InvalidDataException();
        var expiry = DateTimeOffset.Parse(Convert.ToString(rule["expiresAt"])).ToUniversalTime();
        if (operation == "ensure" && expiry <= now) throw new UnauthorizedAccessException("Rule expired.");
        if (operation == "remove") return;
        if (kind == "application")
        {
            string program = Convert.ToString(rule["programPath"]), action = Convert.ToString(rule["action"]);
            if (!Path.IsPathRooted(program) || !program.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || (action != "Allow" && action != "Block")) throw new InvalidDataException();
        }
        else
        {
            string address = Convert.ToString(rule["remoteAddress"]), protocol = Convert.ToString(rule["protocol"]);
            int port = Convert.ToInt32(rule["localPort"]);
            if (kind != "inbound" || !Regex.IsMatch(address, "^[0-9A-Fa-f:. /]+$") || (protocol != "TCP" && protocol != "UDP") || port < 1 || port > 65535) throw new InvalidDataException();
        }
    }

    private byte[] ReadMachineKey()
    {
        string file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentryGate", "Agent", "firewall-helper.key.dpapi");
        byte[] protectedBytes = Convert.FromBase64String(File.ReadAllText(file).Trim());
        return ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.LocalMachine);
    }

    private void ConsumeNonce(string nonce, DateTimeOffset now)
    {
        string file = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentryGate", "Agent", "FirewallHelper", "firewall-helper-nonces.txt");
        var rows = new List<string>();
        if (File.Exists(file)) foreach (string line in File.ReadAllLines(file)) {
            DateTimeOffset at;
            if (line.Length > 40 && DateTimeOffset.TryParse(line.Substring(0, Math.Min(33, line.Length)), out at) && at > now.AddMinutes(-3)) rows.Add(line);
        }
        if (rows.Any(line => line.EndsWith(" " + nonce, StringComparison.OrdinalIgnoreCase))) throw new UnauthorizedAccessException("Replayed command.");
        rows.Add(now.ToString("o") + " " + nonce);
        if (rows.Count > 2000) rows = rows.Skip(rows.Count - 2000).ToList();
        File.WriteAllLines(file, rows);
    }

    private static bool FixedEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0; for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    public static void Main() { ServiceBase.Run(new FirewallHelperService()); }
}
