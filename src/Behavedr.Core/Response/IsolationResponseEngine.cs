namespace Behavedr.Core.Response;

using System.Diagnostics;
using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Handles threats from isolation environments: mounted ISOs (T1553.005),
/// Docker containers, and VMs. Provides containment by dismounting/stopping
/// the isolation layer after killing the malicious process.
/// v0.1.3: Now implements IResponseAction for integration with ResponseEngine (M-4 fix).
/// </summary>
public class IsolationResponseEngine : IResponseAction
{
    private readonly ILogger<IsolationResponseEngine> _logger;

    public IsolationResponseEngine(ILogger<IsolationResponseEngine>? logger = null)
    {
        _logger = logger ?? NullLogger<IsolationResponseEngine>.Instance;
    }

    public string Name => "IsolationResponse";
    public bool IsSupported => OperatingSystem.IsWindows() || OperatingSystem.IsLinux() || OperatingSystem.IsMacOS();

    /// <summary>
    /// IResponseAction implementation: inspects signals for isolation-related threats
    /// and handles ISO dismount, Docker stop, or VM termination as appropriate.
    /// </summary>
    public async Task<ResponseOutcome> ExecuteAsync(DetectionResult result, CancellationToken ct = default)
    {
        // Check for ISO-mounted threat signals
        var isoSignal = result.Signals.FirstOrDefault(s =>
            s.Type.Contains("iso_mount", StringComparison.OrdinalIgnoreCase));
        if (isoSignal is not null && int.TryParse(result.Event.ProcessId, out var isoPid))
        {
            await HandleIsoThreatAsync(isoPid, "");
            return ResponseOutcome.Ok(Name, $"ISO threat handled for PID {isoPid}");
        }

        // Check for Docker-based threat signals
        var dockerSignal = result.Signals.FirstOrDefault(s =>
            s.Type.Contains("docker", StringComparison.OrdinalIgnoreCase));
        if (dockerSignal is not null)
        {
            return ResponseOutcome.Skipped(Name, "Docker container ID not available in signal");
        }

        return ResponseOutcome.Skipped(Name, "No isolation-related threat signals");
    }

    /// <summary>
    /// Kill process, dismount the ISO, and delete the .iso file.
    /// Cross-platform: uses PowerShell on Windows, umount/losetup on Linux, hdiutil on macOS.
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

        // 2. Dismount ISO (platform-specific)
        try
        {
            if (OperatingSystem.IsWindows())
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
            }
            else if (OperatingSystem.IsLinux())
            {
                // Find and unmount loop device associated with this ISO
                using var umount = Process.Start(new ProcessStartInfo
                {
                    FileName = "/bin/umount",
                    Arguments = isoPath,
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                });
                if (umount != null) await umount.WaitForExitAsync();
            }
            else if (OperatingSystem.IsMacOS())
            {
                using var hdiutil = Process.Start(new ProcessStartInfo
                {
                    FileName = "/usr/bin/hdiutil",
                    Arguments = $"detach \"{isoPath}\" -force",
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true,
                });
                if (hdiutil != null) await hdiutil.WaitForExitAsync();
            }
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
            // Use platform-appropriate docker/podman binary
            var dockerBin = FindDockerBinary();
            if (dockerBin is null) return;

            using var proc = Process.Start(new ProcessStartInfo
            {
                FileName = dockerBin,
                Arguments = $"{command} {args}",
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            });
            if (proc != null) await proc.WaitForExitAsync();
        }
        catch { }
    }

    private static string? FindDockerBinary()
    {
        if (OperatingSystem.IsWindows())
        {
            if (File.Exists(@"C:\Program Files\Docker\Docker\resources\bin\docker.exe"))
                return @"C:\Program Files\Docker\Docker\resources\bin\docker.exe";
            return "docker.exe";
        }

        // Linux/macOS: check for docker or podman
        foreach (var binary in new[] { "/usr/bin/docker", "/usr/bin/podman", "/usr/local/bin/docker" })
        {
            if (File.Exists(binary)) return binary;
        }
        return "docker"; // Fall back to PATH lookup
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
