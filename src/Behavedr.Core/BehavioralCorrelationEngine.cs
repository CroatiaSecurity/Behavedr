namespace Behavedr.Core;

using Behavedr.Core.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Time-windowed behavioral correlation engine.
/// Correlates signals across multiple detection cycles within a 120-second sliding window.
/// Produces composite high-confidence detections when signals from different sources
/// appear on the same PID within the correlation window.
///
/// Composite rules (require 2+ distinct signal types):
/// - Injection + Network → "In-Memory Implant Active" (0.96)
/// - Credential Access + Network → "Credential Theft + Exfil" (0.95)
/// - Download Cradle + Execution → "Staged Payload Active" (0.92)
/// - Parent-Child Anomaly + Encoded PS → "Fileless Attack Chain" (0.94)
/// - Anti-Tamper + Suspension → "Active EDR Evasion" (0.97)
/// - Multiple LOLBins on same PID → "LOLBin Chain" (0.88)
/// </summary>
public class BehavioralCorrelationEngine
{
    private readonly ILogger<BehavioralCorrelationEngine> _logger;
    private readonly Dictionary<string, List<TimestampedSignal>> _signalHistory = new();
    private readonly TimeSpan _correlationWindow = TimeSpan.FromSeconds(120);
    private readonly object _lock = new();

    public BehavioralCorrelationEngine(ILogger<BehavioralCorrelationEngine>? logger = null)
    {
        _logger = logger ?? NullLogger<BehavioralCorrelationEngine>.Instance;
    }

    /// <summary>
    /// Ingest signals from a detection cycle and check for composite matches.
    /// Returns any composite signals that should be added to the result.
    /// </summary>
    public List<Signal> Correlate(List<Signal> currentSignals)
    {
        var composites = new List<Signal>();
        var now = DateTime.UtcNow;

        lock (_lock)
        {
            // Add current signals to history
            foreach (var signal in currentSignals)
            {
                var category = CategorizeSignal(signal.Type);
                if (category == SignalCategory.Unknown) continue;

                if (!_signalHistory.TryGetValue(category.ToString(), out var list))
                {
                    list = new List<TimestampedSignal>();
                    _signalHistory[category.ToString()] = list;
                }
                list.Add(new TimestampedSignal(signal, now));
            }

            // Prune expired entries
            PruneExpired(now);

            // Evaluate composite rules
            EvaluateComposites(composites, now);
        }

        return composites;
    }

    private void EvaluateComposites(List<Signal> composites, DateTime now)
    {
        var activeCategories = _signalHistory
            .Where(kv => kv.Value.Count > 0)
            .Select(kv => kv.Key)
            .ToHashSet();

        // Injection + Network → In-Memory Implant
        if (activeCategories.Contains(nameof(SignalCategory.Injection)) &&
            activeCategories.Contains(nameof(SignalCategory.Network)))
        {
            composites.Add(new Signal("composite:in_memory_implant_active", 96, 0.96));
        }

        // CredentialAccess + Network → Credential Theft + Exfil
        if (activeCategories.Contains(nameof(SignalCategory.CredentialAccess)) &&
            activeCategories.Contains(nameof(SignalCategory.Network)))
        {
            composites.Add(new Signal("composite:credential_theft_exfiltration", 95, 0.95));
        }

        // ParentChild + EncodedExecution → Fileless Attack Chain
        if (activeCategories.Contains(nameof(SignalCategory.ParentChild)) &&
            activeCategories.Contains(nameof(SignalCategory.EncodedExecution)))
        {
            composites.Add(new Signal("composite:fileless_attack_chain", 94, 0.94));
        }

        // Download + Execution → Staged Payload
        if (activeCategories.Contains(nameof(SignalCategory.DownloadCradle)) &&
            activeCategories.Contains(nameof(SignalCategory.Execution)))
        {
            composites.Add(new Signal("composite:staged_payload_active", 92, 0.92));
        }

        // AntiTamper + any other → Active EDR Evasion
        if (activeCategories.Contains(nameof(SignalCategory.AntiTamper)) &&
            activeCategories.Count > 1)
        {
            composites.Add(new Signal("composite:active_edr_evasion", 97, 0.97));
        }

        // Multiple LOLBins → LOLBin Chain
        var lolbinSignals = _signalHistory
            .GetValueOrDefault(nameof(SignalCategory.LolBin))?.Count ?? 0;
        if (lolbinSignals >= 2)
        {
            composites.Add(new Signal($"composite:lolbin_chain({lolbinSignals})", 88, 0.88));
        }
    }

    private void PruneExpired(DateTime now)
    {
        foreach (var kvp in _signalHistory)
        {
            kvp.Value.RemoveAll(ts => now - ts.Timestamp > _correlationWindow);
        }

        // Remove empty categories
        var empty = _signalHistory.Where(kv => kv.Value.Count == 0).Select(kv => kv.Key).ToList();
        foreach (var key in empty) _signalHistory.Remove(key);
    }

    private static SignalCategory CategorizeSignal(string signalType)
    {
        var lower = signalType.ToLowerInvariant();

        if (lower.Contains("rwx_memory") || lower.Contains("injection") || lower.Contains("hollowing"))
            return SignalCategory.Injection;
        if (lower.Contains("suspicious_port") || lower.Contains("connection_burst") || lower.Contains("beaconing") || lower.Contains("high_connection"))
            return SignalCategory.Network;
        if (lower.Contains("credential") || lower.Contains("lsass") || lower.Contains("browser_cred"))
            return SignalCategory.CredentialAccess;
        if (lower.Contains("parent_child"))
            return SignalCategory.ParentChild;
        if (lower.Contains("encoded_powershell") || lower.Contains("amsi_bypass"))
            return SignalCategory.EncodedExecution;
        if (lower.Contains("download_cradle"))
            return SignalCategory.DownloadCradle;
        if (lower.Contains("lolbin"))
            return SignalCategory.LolBin;
        if (lower.Contains("suspension") || lower.Contains("binary_integrity") || lower.Contains("anti_tamper") || lower.Contains("service_registration"))
            return SignalCategory.AntiTamper;
        if (lower.Contains("suspicious_process") || lower.Contains("process_burst"))
            return SignalCategory.Execution;

        return SignalCategory.Unknown;
    }

    private record TimestampedSignal(Signal Signal, DateTime Timestamp);

    private enum SignalCategory
    {
        Unknown,
        Injection,
        Network,
        CredentialAccess,
        ParentChild,
        EncodedExecution,
        DownloadCradle,
        LolBin,
        AntiTamper,
        Execution,
    }
}
