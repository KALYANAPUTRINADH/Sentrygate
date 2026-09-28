using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal static class ServiceHost
{
    private const int SERVICE_WIN32_OWN_PROCESS = 0x10;
    private const int SERVICE_START_PENDING = 2, SERVICE_RUNNING = 4, SERVICE_STOP_PENDING = 3, SERVICE_STOPPED = 1;
    private const int SERVICE_ACCEPT_STOP = 1, SERVICE_CONTROL_STOP = 1;
    private static string serviceName = "SentryGateAgent";
    private static string[] launchArgs;
    private static Process child;
    private static volatile bool stopping;
    private static SERVICE_STATUS_HANDLE statusHandle;

    [StructLayout(LayoutKind.Sequential)] private struct SERVICE_TABLE_ENTRY { public string name; public ServiceMainDelegate main; }
    [StructLayout(LayoutKind.Sequential)] private struct SERVICE_STATUS { public int serviceType, currentState, controlsAccepted, win32ExitCode, serviceSpecificExitCode, checkpoint, waitHint; }
    private delegate void ServiceMainDelegate(int argc, IntPtr argv);
    private delegate int HandlerDelegate(int control, int eventType, IntPtr eventData, IntPtr context);
    private static readonly ServiceMainDelegate serviceMain = ServiceMain;
    private static readonly HandlerDelegate handler = HandleControl;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool StartServiceCtrlDispatcher([In] SERVICE_TABLE_ENTRY[] table);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern SERVICE_STATUS_HANDLE RegisterServiceCtrlHandlerEx(string name, HandlerDelegate callback, IntPtr context);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetServiceStatus(SERVICE_STATUS_HANDLE handle, ref SERVICE_STATUS status);
    [StructLayout(LayoutKind.Sequential)] private struct SERVICE_STATUS_HANDLE { public IntPtr value; public static implicit operator SERVICE_STATUS_HANDLE(IntPtr p) { return new SERVICE_STATUS_HANDLE { value = p }; } }
    private static SERVICE_STATUS current;

    private static void Main(string[] args)
    {
        launchArgs = args;
        if (args.Length < 3) Environment.Exit(2);
        var table = new[] { new SERVICE_TABLE_ENTRY { name = serviceName, main = serviceMain }, new SERVICE_TABLE_ENTRY() };
        if (!StartServiceCtrlDispatcher(table)) Environment.Exit(Marshal.GetLastWin32Error());
    }
    private static void ServiceMain(int argc, IntPtr argv)
    {
        statusHandle = RegisterServiceCtrlHandlerEx(serviceName, handler, IntPtr.Zero);
        if (statusHandle.value == IntPtr.Zero) return;
        SetState(SERVICE_START_PENDING, 0, 10000);
        try
        {
            var start = new ProcessStartInfo { FileName = launchArgs[0], Arguments = "\"" + launchArgs[1] + "\"", WorkingDirectory = System.IO.Path.GetDirectoryName(launchArgs[1]), UseShellExecute = false, CreateNoWindow = true };
            start.EnvironmentVariables["SENTRYGATE_AGENT_CONFIG"] = launchArgs[2];
            if (launchArgs.Length > 3 && !String.IsNullOrWhiteSpace(launchArgs[3]))
                start.EnvironmentVariables["NODE_EXTRA_CA_CERTS"] = launchArgs[3];
            child = Process.Start(start);
            SetState(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0);
            child.WaitForExit();
            var exitCode = child.ExitCode;
            SetState(SERVICE_STOPPED, 0, !stopping && exitCode != 0 ? 1 : 0);
            Environment.ExitCode = !stopping && exitCode != 0 ? 1 : 0;
        }
        catch { SetState(SERVICE_STOPPED, 0, 1); Environment.ExitCode = 1; }
    }
    private static int HandleControl(int control, int eventType, IntPtr eventData, IntPtr context)
    {
        if (control == SERVICE_CONTROL_STOP)
        {
            stopping = true;
            SetState(SERVICE_STOP_PENDING, 0, 10000);
            try { if (child != null && !child.HasExited) { child.Kill(); child.WaitForExit(10000); } } catch { }
        }
        return 0;
    }
    private static void SetState(int state, int accepted, int wait)
    {
        current.serviceType = SERVICE_WIN32_OWN_PROCESS; current.currentState = state; current.controlsAccepted = accepted;
        current.win32ExitCode = 0; current.serviceSpecificExitCode = 0; current.checkpoint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 1 : 0; current.waitHint = wait;
        SetServiceStatus(statusHandle, ref current);
    }
}
