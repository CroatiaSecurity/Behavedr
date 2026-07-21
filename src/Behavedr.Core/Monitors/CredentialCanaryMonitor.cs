namespace Behavedr.Core.Monitors;

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Behavedr.Core.Models;
using Behavedr.Core.Platform;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Credential honeypot (canary) using Windows Credential Manager.
/// Deploys a fake credential at startup. If anyone reads or deletes it, that's
/// a near-zero false positive indicator of credential harvesting.
/// Confidence: 0.98 (only credential dumpers/infostealers would access this).
/// </summary>
[SupportedOSPlatform("windows")]
public class CredentialCanaryMonitor : IPlatformMonitor
{
    private readonly ILogger<CredentialCanaryMonitor> _logger;
    private bool _canaryDeployed;
    private bool _canaryTripped;
    private const string CanaryTarget = "WindowsLive:target=wl_blob:behavedr-internal-svc";
    private const string CanaryUser = "svc-internal@corp.local";

    public string PlatformName => "CredentialCanary";
    public bool IsSupported => OperatingSystem.IsWindows();

    public CredentialCanaryMonitor(ILogger<CredentialCanaryMonitor>? logger = null)
    {
        _logger = logger ?? NullLogger<CredentialCanaryMonitor>.Instance;
    }

    [SupportedOSPlatform("windows")]
    public Task<IEnumerable<Signal>> GetSignalsAsync(CancellationToken ct = default)
    {
        var signals = new List<Signal>();

        if (!_canaryDeployed)
        {
            DeployCanary();
            _canaryDeployed = true;
            return Task.FromResult<IEnumerable<Signal>>(signals);
        }

        // Check if canary credential still exists
        if (!_canaryTripped && !CanaryExists())
        {
            _canaryTripped = true;
            signals.Add(new Signal("credential_canary_tripped:deleted", 95, 0.98));
            _logger.LogCritical(
                "SECURITY: Credential canary TRIPPED — honeypot credential was accessed/deleted. " +
                "This is a near-certain indicator of credential harvesting activity.");

            // Re-deploy to catch repeated harvesting
            DeployCanary();
            _canaryTripped = false;
        }

        return Task.FromResult<IEnumerable<Signal>>(signals);
    }

    [SupportedOSPlatform("windows")]
    private void DeployCanary()
    {
        try
        {
            var cred = new CREDENTIAL
            {
                Type = CRED_TYPE_GENERIC,
                TargetName = CanaryTarget,
                UserName = CanaryUser,
                CredentialBlobSize = 32,
                CredentialBlob = System.Text.Encoding.UTF8.GetBytes("Behavedr-Canary-2026-Do-Not-Use!"),
                Persist = CRED_PERSIST_LOCAL_MACHINE,
                Comment = "Internal service credential (do not modify)"
            };

            if (CredWrite(ref cred, 0))
                _logger.LogInformation("[CredentialCanary] Honeypot credential deployed");
            else
                _logger.LogDebug("[CredentialCanary] Failed to deploy canary credential");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[CredentialCanary] Deploy failed");
        }
    }

    [SupportedOSPlatform("windows")]
    private bool CanaryExists()
    {
        try
        {
            return CredRead(CanaryTarget, CRED_TYPE_GENERIC, 0, out var credPtr) && credPtr != IntPtr.Zero;
        }
        catch { return false; }
    }

    // P/Invoke for Credential Manager
    private const int CRED_TYPE_GENERIC = 1;
    private const int CRED_PERSIST_LOCAL_MACHINE = 2;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public byte[] CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredWrite(ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credentialPtr);
}
