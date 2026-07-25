using Behavedr.Core;
using Behavedr.Core.Communication;
using Behavedr.Core.Platform;
using Behavedr.Core.Response;

namespace Behavedr.Tests;

public class PolicyApplicatorTests
{
    [Fact]
    public void TryApply_UpdatesResponseAndInterval()
    {
        var response = new ResponseEngine(ResponsePolicy.Default);
        var scoring = new ScoringEngine();
        var live = new LivePolicyState { MonitoringIntervalSeconds = 5 };
        var app = new PolicyApplicator(response, scoring, live);

        var update = new PolicyUpdate(
            ResponsePolicy: new ResponsePolicy
            {
                Mode = ResponseMode.Active,
                AlertThreshold = 40,
                ResponseThreshold = 70,
                MaxKillsPerMinute = 10,
            },
            ScoringConfig: new ScoringConfig
            {
                UserTargetedMultiplier = 2.0,
                PresidentKillThreshold = 90,
                HighScoreAlertThreshold = 40,
            },
            MonitoringIntervalSeconds: 3,
            IssuedAt: DateTime.UtcNow,
            Signature: null); // no signature — applicator re-verifies only when Signature set

        // Empty signature: VerifySignature returns false if called — PolicyApplicator only
        // verifies when Signature is non-empty. Match that contract.
        Assert.True(app.TryApply(update, out var err), err);
        Assert.Equal(ResponseMode.Active, response.Policy.Mode);
        Assert.Equal(70, response.Policy.ResponseThreshold);
        Assert.Equal(3, live.MonitoringIntervalSeconds);
        Assert.NotNull(live.LastPolicyAppliedUtc);
        Assert.Equal(90, scoring.PresidentKillThreshold);
    }

    [Fact]
    public void TryUpdatePolicy_RejectsInvalid()
    {
        var engine = new ResponseEngine();
        var bad = new ResponsePolicy
        {
            AlertThreshold = 90,
            ResponseThreshold = 10, // invalid: respond < alert
        };
        Assert.False(engine.TryUpdatePolicy(bad, out _));
    }

    [Fact]
    public void TryApply_RejectsBadSignature()
    {
        var response = new ResponseEngine();
        var scoring = new ScoringEngine();
        var live = new LivePolicyState();
        var app = new PolicyApplicator(response, scoring, live);

        var update = new PolicyUpdate(
            null, null, 5, DateTime.UtcNow,
            Signature: Convert.ToBase64String(new byte[256]));

        Assert.False(app.TryApply(update, out var err));
        Assert.Contains("signature", err, StringComparison.OrdinalIgnoreCase);
    }
}
