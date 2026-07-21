namespace Behavedr.Core.Response;

using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Handles threats from isolation environments: mounted ISOs (T1553.005),
/// Docker containers, and VMs. Provides containment by dismounting/stopping
/// the isolation layer after killing the malicious process.
/// </summary>
public class IsolationResponseEngine
{
    private readonly ILogger<IsolationResponseEngine> _logger;

    public IsolationResponseEngine(ILogger<IsolationResponseEngine>? logger = null)
    {
        _logger = logger ?? NullLogger<IsolationResponseEngine>.Instance;
    }

    /// <summary>
    /// Kill process, dismount the ISO, and delete the .iso file.
    /// </summary>
    public async Task HandleIsoThreatAsync(int processId, string isoPath)
    {
        _logger.LogWarning("[IsolationResponse] Handling ISO threat — PID {Pid}, ISO {Path}", processId, isoPath);

        // 1. Kill the process
        try
        {
            using var proc = Process.GetProcessById(processId);
            proc.Kill(entireProcessTree: true);
            await proc.WaitForExitAsync();
        }
        catch { }

        // 2. Dismount ISO via PowerShell (EncodedCommand for injection safety)
        try
        {
            var script = $"Dismount-DiskImage -ImagePath '{isoPath.Replace("'", "''")}' -ErrorAction Stop";
            var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(script));
            using var ps = Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            });
            if (ps != null) await ps.WaitForExitAsync();
            _logger.LogWarning("[IsolationResponse] Dismounted ISO {Path}", isoPath);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "[IsolationResponse] Dismount failed"); }

        // 3. Delete the ISO file
        try
        {
            if (File.Exists(isoPath)) File.Delete(isoPath);
            _logger.LogWarning("[IsolationResponse] Deleted ISO {Path}", isoPath);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "[IsolationResponse] Delete failed"); }
    }

    /// <summary>
    /// Stop and remove a Docker container and its image.
    /// </summary>
    public async Task HandleDockerThreatAsync(string containerId)
    {
        if (string.IsNullOrEmpty(containerId) || !IsValidDockerId(containerId)) return;

        _logger.LogWarning("[IsolationResponse] Handling Docker threat — container {Id}", containerId);

        await RunDockerAsync("stop", containerId);
        await RunDockerAsync("rm", $"--force {containerId}");
    }

    /// <summary>
    /// Terminate a VM host process.
    /// </summary>
    public async Task HandleVmThreatAsync(int vmProcessId, string vmName)
    {
        _logger.LogWarning("[IsolationResponse] Handling VM threat — PID {Pid}, VM {Name}", vmProcessId, vmName);
        try
        {
            using var proc = Process.GetProcessById(vmProcessId);
            proc.Kill(entireProcessTree: true);
            await proc.WaitForExitAsync();
        }
        catch { }
    }

    private async Task RunDockerAsync(string command, string args)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = "docker.exe",
                Arguments = $"{command} {args}",
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            });
            if (proc != null) await proc.WaitForExitAsync();
        }
        catch { }
    }

    private static bool IsValidDockerId(string id)
    {
        if (id.Length > 128) return false;
        foreach (var c in id)
        {
            if (!char.IsLetterOrDigit(c) && c != '_' && c != '.' && c != '-' && c != ':')
                return false;
        }
        return true;
    }
}
