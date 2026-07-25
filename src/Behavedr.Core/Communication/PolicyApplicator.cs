namespace Behavedr.Core.Communication;

using Behavedr.Core.Platform;
using Behavedr.Core.Response;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Applies a verified <see cref="PolicyUpdate"/> to live engines (v0.3.1).
/// Signature verification must already have succeeded (e.g. in GrpcBehavedrClient).
/// </summary>
public sealed class PolicyApplicator
{
    private readonly ResponseEngine _response;
    private readonly ScoringEngine _scoring;
    private readonly LivePolicyState _live;
    private readonly ILogger<PolicyApplicator> _logger;

    public PolicyApplicator(
        ResponseEngine response,
        ScoringEngine scoring,
        LivePolicyState live,
        ILogger<PolicyApplicator>? logger = null)
    {
        _response = response;
        _scoring = scoring;
        _live = live;
        _logger = logger ?? NullLogger<PolicyApplicator>.Instance;
    }

    public bool TryApply(PolicyUpdate policy, out string error)
    {
        ArgumentNullException.ThrowIfNull(policy);
        error = "";

        if (!string.IsNullOrEmpty(policy.Signature) && !policy.VerifySignature())
        {
            error = "signature invalid";
            Telemetry.SecurityTelemetry.ReportSignatureFailure();
            return false;
        }

        var applied = new List<string>();

        if (policy.ResponsePolicy is not null)
        {
            if (!_response.TryUpdatePolicy(policy.ResponsePolicy, out var re))
            {
                error = re;
                return false;
            }
            applied.Add("response");
        }

        if (policy.ScoringConfig is not null)
        {
            if (!_scoring.TryUpdateConfig(policy.ScoringConfig, out var se))
            {
                error = se;
                return false;
            }
            applied.Add("scoring");
        }

        if (policy.MonitoringIntervalSeconds is int secs)
        {
            _live.MonitoringIntervalSeconds = secs;
            applied.Add($"interval={_live.MonitoringIntervalSeconds}s");
        }

        if (applied.Count == 0)
        {
            error = "empty policy payload";
            return false;
        }

        _live.MarkApplied();
        _logger.LogWarning("Applied signed policy ({Parts}) issued {Issued}",
            string.Join(",", applied), policy.IssuedAt);
        return true;
    }
}
