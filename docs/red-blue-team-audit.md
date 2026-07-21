# Behavedr EDR — Red/Blue Team Security Audit

**Date:** 2026-07-21  
**Version Audited:** 0.0.6  
**Auditor:** AI-assisted security analysis  
**Cross-reference:** Sentinel EDR v1.5.4 (Windows-only EDR for pattern comparison)  
**Scope:** Full source code review, architecture analysis, evasion modeling  

---

## Executive Summary

Behavedr is a promising multi-platform behavioral EDR with solid cryptographic foundations (AES-256-GCM, HKDF, mTLS, RSA-PSS signing) and good defensive coding practices (path traversal prevention, rate limiting, fail-closed TLS). However, as a **v0.0.6 project**, it has critical gaps that make it trivially bypassable by even commodity malware. The most severe issues are:

1. **Placeholder signing key** — updates and policies are effectively unsigned
2. **Process-name-only detection** — trivially evaded by renaming binaries
3. **No ETW integration** — polling-based detection has multi-second blind spots
4. **No network monitoring** — C2 traffic is completely invisible
5. **No anti-tamper beyond basic debugger check** — attacker can kill/suspend/blind the agent

Compared to Sentinel's 70+ monitors, unified ETW session, behavioral correlation, and active deception, Behavedr currently operates at approximately 5-10% of the detection surface area needed for production deployment.

---

## RED TEAM ANALYSIS — Attack Scenarios & Exploitable Gaps

### RT-1: Update Supply Chain Hijack (CRITICAL)

**Attack:** Attacker compromises the GitHub release or performs MITM to serve a malicious update zip.

**Current State:**
- `UpdateSignatureVerifier.cs` contains a **PLACEHOLDER** RSA public key (`0PLACEHOLDER000...`)
- `IsProductionKeyConfigured()` returns `false` → signature verification is **skipped entirely**
- `AutoUpdater.ApplyUpdateAsync()` logs a warning but proceeds without verification in dev mode

**Exploitability:** Trivial. Any attacker controlling DNS or GitHub can push arbitrary code.

**Impact:** Complete agent compromise — attacker replaces the EDR binary with their own.

**Recommendation:** Generate a real RSA-4096 keypair immediately. Embed the public key. Sign all releases. Never ship with the placeholder.

---

### RT-2: Process Name Evasion (CRITICAL)

**Attack:** Rename offensive tools to bypass detection.

**Current State (WindowsMonitor.cs):**
```csharp
private static readonly HashSet<string> SuspiciousProcessNames = new(...)
{
    "mimikatz", "psexec", "cobalt", "meterpreter", ...
};
// Detection: name.Contains(suspiciousName)
```

**Exploitability:** Trivial. Rename `mimikatz.exe` to `updater.exe` → zero detection.

**Impact:** All Windows process-name-based detections are bypassed with a single rename.

**What Sentinel does differently:** Sentinel uses behavioral signals (API calls via ETW ThreatIntel provider, memory patterns, parent-child anomalies) rather than process names. Process names are metadata enrichment only, never detection triggers.

---

### RT-3: EDR Process Termination (CRITICAL)

**Attack:** `taskkill /f /im Behavedr.exe` or BYOVD kernel-level kill.

**Current State:**
- `SelfProtectionService.cs` detects debuggers and checks binary integrity
- No anti-termination mechanism (no deny-terminate handle protection)
- No watchdog process that survives agent death
- No service recovery beyond standard SCM restart
- No WFP monitoring — attacker can silently block all agent network traffic

**Exploitability:** Trivial with admin access. One command kills the EDR permanently.

**Impact:** Complete EDR bypass. Agent dies, no forensic evidence survives.

**What Sentinel does differently:**
- `AntiTamperGuard`: Denies `PROCESS_TERMINATE` on own handles, detects suspension gaps via QPC timing, auto-reinstalls service registry entries
- `AgentWatchdog`: Separate SYSTEM service restarts agent in user session via `CreateProcessAsUser`
- Mutual monitoring between Service and Agent processes
- Last-gasp logging on unexpected exit

---

### RT-4: Network Blindness — No C2 Detection (HIGH)

**Attack:** Any C2 framework (Cobalt Strike, Sliver, Havoc) communicates freely over HTTPS.

**Current State:** Behavedr has **zero network monitoring**. No TCP table scanning, no DNS monitoring, no beaconing detection, no connection tracking.

**Exploitability:** Trivial. All network-based attacks are invisible.

**Impact:** Attackers maintain persistent C2 access indefinitely without detection.

**What Sentinel does:** `NetworkMonitor` (TCP/UDP table scanning), `BeaconingDetector` (statistical CV analysis), `DnsQueryMonitor` (ETW DNS-Client), `GhostProcessMonitor` (PIDs with connections but no process name), `DataExfiltrationMonitor` (large outbound transfers).

---

### RT-5: No ETW — Detection Latency & Blind Spots (HIGH)

**Attack:** Fast-acting malware completes its mission before the 5-second polling interval fires.

**Current State:**
- `MonitoringService.cs` polls every 5 seconds (configurable, minimum 1s)
- `WindowsMonitor` uses `Process.GetProcesses()` — userland snapshot, no kernel visibility
- No ETW Threat Intelligence provider (misses VirtualAllocEx, VirtualProtect, MapViewOfSection)
- No ETW Kernel-Process (misses process creation events in real-time)

**Exploitability:** High. Any malware that executes and exits within 5 seconds is never observed.

**Impact:** Credential stealers (complete in <3s), fileless attacks, injection attacks all invisible.

**What Sentinel does:** `UnifiedEtwSession` subscribes to 9 kernel/system providers simultaneously, achieving ~50ms detection latency vs Behavedr's 5000ms.

---

### RT-6: Policy Update Forgery (HIGH)

**Attack:** MITM or rogue server sends malicious policy update to reconfigure scoring thresholds.

**Current State:**
- `PolicyUpdate.VerifySignature()` uses the same placeholder public key
- When `IsProductionKeyConfigured()` returns false, verification returns `true` unconditionally
- An attacker could set `PresidentKillThreshold` to 999.0, effectively disabling all response

**Exploitability:** Medium (requires network position). With placeholder key: trivial.

**Impact:** Attacker remotely disarms all detection/response by pushing benign-looking policy.

---

### RT-7: Scoring Manipulation via Signal Flooding (MEDIUM)

**Attack:** Generate benign signals to dilute scoring or exploit unbounded score accumulation.

**Current State:**
- `ScoringEngine.CalculateScore()` does NOT clamp to 100 — scores can grow unbounded
- No deduplication of signals within a cycle
- If a monitor returns 1000 low-weight signals, the score inflates artificially
- No decay/aging of signals between cycles

**Exploitability:** Medium. Requires understanding of the scoring algorithm.

**Impact:** Either false positives (causing alert fatigue) or manipulation of thresholds.

---

### RT-8: Config Integrity Bypass — First-Run Window (MEDIUM)

**Attack:** Modify `appsettings.json` before the agent's first run to set favorable thresholds.

**Current State (Program.cs):**
```csharp
case ConfigIntegrityResult.NotSealed:
    Log.Warning("Config file not yet sealed — sealing now (first run)");
    ConfigIntegrity.SealConfigFile(configPath);
    break;
```

**Exploitability:** Medium. Attacker who can write to the install directory pre-first-run wins.

**Impact:** Permanently tampered config is sealed as "legitimate" — agent trusts malicious values forever.

**Fix:** Ship a pre-sealed config with the installer. Or seal against a known-good embedded hash.

---

### RT-9: Machine Key Extraction (MEDIUM)

**Attack:** Extract `.behavedr-key` to decrypt offline buffer, forge config HMACs, or decrypt sensitive config values.

**Current State:**
- Key stored in `C:\ProgramData\Behavedr\.behavedr-key` (base64 plaintext)
- On Windows: `RestrictFileToAdminsAndSystem()` is called but the method implementation is cut off in the source
- On Linux: `chmod 600` (user read/write only)
- Key is a single file — no hardware binding (no TPM, no DPAPI)

**Exploitability:** Medium-High with admin access. Read one file → decrypt everything.

**What Sentinel does:** Uses DPAPI (machine-scope) for key protection, incorporates installation entropy into HMAC derivation, binds cache to boot nonce.

---

### RT-10: Linux Monitor Evasion — /proc Race Conditions (MEDIUM)

**Attack:** Process exits before LinuxMonitor's /proc scan reaches its PID directory.

**Current State:**
- `LinuxMonitor.ScanProcFilesystem()` iterates `/proc/[pid]/comm` sequentially
- No event-driven detection (no eBPF, no auditd subscription, no fanotify)
- Audit log reading is best-effort (last 8KB, 30-second cutoff)

**Exploitability:** High for fast-acting malware. Moderate for persistent threats.

**Impact:** Short-lived processes (droppers, stagers) never observed on Linux.

---

### RT-11: Android Signal Injection Token Weakness (LOW-MEDIUM)

**Attack:** If attacker can read the injection token from memory or inter-process communication, they can inject false signals.

**Current State:**
- `AndroidMonitor.SetInjectionToken()` uses a string comparison
- Token is stored in-memory in a `private string? _injectionToken`
- No cryptographic binding to caller identity

**Exploitability:** Low (requires same-process memory access or IPC interception on Android).

**Impact:** Attacker could inject fake "safe" signals or trigger false positives.

---

### RT-12: Response Engine Default Mode — AlertOnly (LOW)

**Attack:** Behavedr defaults to `ResponseMode.AlertOnly` — even if threats are detected, no action is taken.

**Current State:**
- `ResponsePolicy.Default` sets `Mode = ResponseMode.AlertOnly`
- Unless explicitly configured to `Active`, the agent is observe-only
- An attacker who knows this can operate freely as long as no human reviews logs

**Impact:** Low (by design for safety), but means the EDR provides zero active protection out-of-box.

---

## RED TEAM SUMMARY TABLE

| # | Gap | Severity | Exploitability | Current Mitigation |
|---|-----|----------|---------------|-------------------|
| RT-1 | Placeholder signing key | CRITICAL | Trivial | None (skipped in dev) |
| RT-2 | Process-name-only detection | CRITICAL | Trivial | None |
| RT-3 | No anti-termination | CRITICAL | Trivial (admin) | SCM restart only |
| RT-4 | No network monitoring | HIGH | Trivial | None |
| RT-5 | No ETW (5s polling gaps) | HIGH | High | None |
| RT-6 | Policy forgery (placeholder key) | HIGH | Medium | None effective |
| RT-7 | Score manipulation | MEDIUM | Medium | Partial (confidence clamp) |
| RT-8 | First-run config window | MEDIUM | Medium | None |
| RT-9 | Machine key extraction | MEDIUM | Medium-High (admin) | File ACLs |
| RT-10 | Linux /proc race conditions | MEDIUM | High | None |
| RT-11 | Android token weakness | LOW-MEDIUM | Low | String comparison |
| RT-12 | AlertOnly default | LOW | N/A | By design |

---

## BLUE TEAM ANALYSIS — Defensive Strengths & Gaps

### What Behavedr Does Well (Strengths)

#### S1: Cryptographic Architecture
- AES-256-GCM authenticated encryption for data at rest (SecureEnvelope)
- HKDF key derivation with purpose-specific context labels
- HMAC-SHA256 config integrity with constant-time comparison
- RSA-PSS SHA-256 for update/policy signing (when key is real)
- Proper nonce generation via `RandomNumberGenerator`

#### S2: Fail-Closed Communication
- `GrpcBehavedrClient` rejects ALL server connections when no CA cert is configured
- Certificate pinning via custom X509Chain validation
- mTLS with client certificates for agent authentication
- No `DangerousAcceptAnyServerCertificateValidator` anywhere in codebase

#### S3: Supply Chain Awareness
- `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` in Directory.Build.props
- `<Deterministic>true</Deterministic>` for reproducible builds
- `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`
- Pinned NuGet package versions (lock file)

#### S4: Path Traversal Prevention
- `FileQuarantineAction.IsValidFileName()` rejects `..`, `/`, `\`, null bytes
- Resolved path verified against expected directory with `Path.GetFullPath()`
- `AutoUpdater` has Zip Slip protection (rejects entries resolving outside target dir)

#### S5: Response Safety
- Rate limiting (60s cooldown per target PID:ProcessName)
- Protected process list (never kills csrss, lsass, svchost, explorer, etc.)
- PID reuse validation (double-checks process name matches before kill)
- AlertOnly default mode prevents accidental production damage

#### S6: Offline Resilience
- Encrypted offline buffer survives network outages
- Chronological replay on reconnection
- Dead-letter directory for corrupted/tampered reports
- Max buffer size enforcement prevents disk exhaustion

---

### Defensive Gaps (Blue Team Perspective)

#### BT-1: No Behavioral Correlation Engine

**Gap:** Signals are scored independently per cycle. No temporal correlation across cycles.

**Impact:** Cannot detect multi-stage attacks (recon → staging → execution → exfiltration) that span multiple polling intervals. Each 5-second window is evaluated in isolation.

**What Sentinel does:** `BehavioralCorrelationEngine` correlates signals across a 120-second window per-PID. Multiple weak signals from different sources produce composite kills (e.g., "unsigned binary + injection API + C2 network" → 0.98 confidence kill).

---

#### BT-2: No Credential Protection

**Gap:** No monitoring of browser credential files, LSASS access, token theft, or credential canaries.

**Impact:** Infostealers (Lumma, Amatera, RedLine) can freely read Chrome Login Data, Firefox key4.db, Windows credential vaults without triggering any signal.

**What Sentinel does:** `ChromeCredentialGuardMonitor`, `FirefoxCredentialGuardMonitor`, `MicrosoftAccountGuardMonitor`, `LsassDumpCanaryMonitor`, `CredentialCanaryMonitor` — comprehensive credential theft detection with 3-10s scan intervals.

---

#### BT-3: No File Integrity/Activity Monitoring

**Gap:** No `FileSystemWatcher` on sensitive paths. No real-time file I/O monitoring.

**Impact:** Ransomware (bulk file encryption), data staging, DLL sideloading, and sensitive file access all go undetected.

**What Sentinel does:** `FileActivityMonitor` (FileSystemWatcher on user profile + configurable paths), `RansomwareIoMonitor` (shadow copy + bulk rename + I/O rate + extension counting), `ApplicationIntegrityMonitor` (SHA-256 baseline of protected executables).

---

#### BT-4: No Registry Monitoring (Windows)

**Gap:** No detection of persistence via Run keys, scheduled tasks, WMI subscriptions, or service creation.

**Impact:** Attacker establishes persistence silently. No signal generated for any registry-based persistence technique.

**What Sentinel does:** `RegistryMonitor` (ETW Kernel-Registry provider), `ScheduledTaskMonitor`, `WmiPersistenceMonitor`, `PersistenceRule` (covers Run keys, services, WMI, tasks).

---

#### BT-5: No Parent-Child Process Validation

**Gap:** `WindowsMonitor` has `SuspiciousParentChild` dictionary defined but **never uses it** — there's no code that checks parent-child relationships.

**Impact:** Classic attack chains (Word → cmd → PowerShell, Explorer → mshta) go completely undetected.

**What Sentinel does:** `ProcessAncestryCache` (refreshed every 2s), `ParentPidSpoofDetector` (ETW truth vs snapshot comparison), parent-child signals feed into every detection rule.

---

#### BT-6: No Memory Analysis

**Gap:** No scanning for RWX regions, shellcode patterns, process hollowing, or unbacked executables.

**Impact:** In-memory implants (Cobalt Strike Beacon, Meterpreter reflective DLL) operate undetected. Process injection is invisible.

**What Sentinel does:** `MemoryBehaviorAnalyzer` (VirtualQueryEx + ReadProcessMemory, scans every 45s for RWX/shellcode/unbacked), `HollowProcessMonitor` (GetMappedFileName vs module path mismatch), `EtwThreatIntelMonitor` (kernel-level VirtualAllocEx/VirtualProtect observation).

---

#### BT-7: No Deception/Honeypot Capabilities

**Gap:** No canary files, credential honeypots, or deception infrastructure.

**Impact:** Cannot detect reconnaissance or credential harvesting with zero false positives.

**What Sentinel does:** `CredentialCanaryMonitor` (Windows Credential Manager honeypot — 0.98-0.99 confidence, zero FP), `CanaryFileMonitor` (honeypot files in sensitive directories), active deception v1.7.0 (BeaconFlooder, ClipboardPoisonTactic, FileTrapTactic, HoneypotWeaponizer).

---

#### BT-8: No Structured Detection Rules/Tiers

**Gap:** Behavedr has a flat scoring model — all signals contribute equally to a single score. No concept of detection tiers, composite rules, or behavioral correlation.

**Impact:** Cannot differentiate between "slightly suspicious" and "confirmed active attack." No composite detection (e.g., injection + C2 + credential access = confirmed implant).

**What Sentinel does:** Two-tier system — Tier1 (behavioral, kill-authorized) and Tier2 (corroborating, log-only). Composite detections require signals from different sources on the same PID within 120s. President's Law governs which behaviors authorize automated response.

---

#### BT-9: No Telemetry Fusion / Event Graph

**Gap:** Each monitoring cycle is independent. No event chain tracking, no process timeline, no causal graph.

**Impact:** Cannot reconstruct attack timelines, correlate across data sources, or identify multi-vector campaigns.

**What Sentinel does:** `TelemetryFusionEngine` (enriches events with cross-source context, builds temporal chains per-process), `EventGraph` (in-memory graph of processes/files/network with temporal/causal edges), `IncidentManager` (groups related detections into incidents).

---

#### BT-10: No macOS/iOS Monitors Are Implemented

**Gap:** While the architecture supports these platforms, no actual monitor implementations exist for macOS or iOS beyond stubs.

**Impact:** The agent runs but detects nothing on Apple platforms.

---

## CROSS-REFERENCE: Patterns to Import from Sentinel

### Priority 1 — Architectural Patterns (Foundation)

| Sentinel Pattern | What It Provides | Implementation Effort |
|---|---|---|
| **Unified ETW Session** | Real-time kernel-level visibility into process/file/registry/network/DNS events (~50ms latency) | High — requires P/Invoke ETW APIs, but transforms detection from blind to sighted |
| **Tiered Detection Model** | Tier1 (kill-authorized) vs Tier2 (corroborating) prevents single-signal false kills | Medium — restructure ScoringEngine to emit tiered events |
| **Behavioral Correlation Engine** | Time-windowed multi-signal correlation produces composite high-confidence detections | Medium — new component correlating signals across multiple cycles |
| **ProcessAncestryCache** | Enables parent-child validation, ancestry chain analysis for all detections | Low-Medium — CreateToolhelp32Snapshot + refresh loop |
| **TelemetryFusionEngine** | Cross-source enrichment, per-process event chains, behavioral velocity metrics | Medium — new layer between monitors and detection engine |

### Priority 2 — Critical Monitors to Port (Windows)

| Sentinel Monitor | Detection Capability | Port Complexity |
|---|---|---|
| **NetworkMonitor** | `GetExtendedTcpTable`/`GetExtendedUdpTable` — tracks all connections with PID attribution | Low (P/Invoke + polling) |
| **BeaconingDetector** | Statistical C2 detection via connection interval coefficient of variation | Medium (requires NetworkMonitor data) |
| **MemoryBehaviorAnalyzer** | `VirtualQueryEx` + `ReadProcessMemory` — detects RWX, shellcode, unbacked exec | Medium (P/Invoke, careful with permissions) |
| **ChromeCredentialGuardMonitor** | FileSystemWatcher on browser credential files | Low (FileSystemWatcher) |
| **ScheduledTaskMonitor** | `schtasks /query` parsing for malicious task detection | Low (shell command + parse) |
| **RegistryMonitor** | ETW Kernel-Registry or polling of persistence keys | Medium (ETW preferred, registry polling fallback) |
| **HollowProcessMonitor** | `GetMappedFileName` vs loaded module path — detects process hollowing | Medium (P/Invoke) |
| **GhostProcessMonitor** | PIDs with network but no resolvable name — catches DLL sideloading | Low (cross-reference TCP table vs Process.GetProcesses) |

### Priority 3 — Self-Protection Improvements

| Sentinel Pattern | What It Provides |
|---|---|
| **AntiTamperGuard** with QPC timing | Detects suspension attacks via QueryPerformanceCounter (immune to clock manipulation) |
| **AgentWatchdog** (separate process) | Mutual monitoring — if either dies, the other restarts it |
| **Service registry self-healing** | If attacker deletes the service, re-registers via SCM P/Invoke (not sc.exe) |
| **Last-gasp logging** | On unexpected exit, writes forensic evidence before death |
| **ConnectivityCanaryMonitor** | Detects if agent's network is being silenced (WFP/EDRSilencer) |
| **Native SCM P/Invoke** | Avoids shelling out to sc.exe (which can be intercepted/blocked) |

### Priority 4 — Deception Capabilities

| Sentinel Pattern | What It Provides |
|---|---|
| **CredentialCanaryMonitor** | Zero-FP honeypot credential in Windows Credential Manager |
| **CanaryFileMonitor** | Honeypot files in sensitive directories detect reconnaissance |
| **ClipboardPoisonTactic** | Active deception — fake credentials to waste attacker time |
| **NetworkHoneypotDeployer** | Fake service listeners as lateral movement traps |

---

## PRIORITIZED RECOMMENDATIONS

### P0 — Critical (Must Fix Before Any Production Use)

#### 1. Replace Placeholder Signing Key
- Generate RSA-4096 keypair
- Embed real public key in `UpdateSignatureVerifier.cs`
- Sign all release zips and policy updates
- Remove the `IsProductionKeyConfigured()` bypass path entirely in Release builds

#### 2. Add Behavioral Detection (Not Name-Based)
- Remove reliance on `SuspiciousProcessNames` as primary detection
- Implement parent-child anomaly detection (the dictionary exists but is unused!)
- Add command-line argument analysis (encoded PowerShell, download cradles, LOLBin patterns)
- Port Sentinel's approach: detect what processes DO, not what they ARE named

#### 3. Implement ETW Integration (Windows)
- Subscribe to `Microsoft-Windows-Kernel-Process` for real-time process creation
- Subscribe to `Microsoft-Windows-Threat-Intelligence` for injection API observation
- Subscribe to `Microsoft-Windows-DNS-Client` for DNS monitoring
- Fall back to current polling when ETW is unavailable (non-admin)

#### 4. Add Anti-Termination / Watchdog
- Spawn a separate watchdog process with randomized name
- Implement mutual PID monitoring (service watches agent, agent watches service)
- Add `DenyProcessTermination` handle protection where OS supports it
- Register for SCM failure recovery with escalating restart delays

---

### P1 — High Priority (Next Release)

#### 5. Add Network Monitoring
- `GetExtendedTcpTable`/`GetExtendedUdpTable` P/Invoke for connection inventory
- Track new connections per PID per cycle
- Flag connections to known-bad IPs or non-standard ports from suspicious processes
- Implement basic beaconing detection (interval regularity)

#### 6. Add Credential Protection
- `FileSystemWatcher` on Chrome/Edge/Firefox credential database paths
- Alert when non-browser process accesses credential files
- Implement a credential canary (Windows Credential Manager honeypot)

#### 7. Implement Behavioral Correlation
- Maintain per-PID signal history across cycles (120s sliding window)
- Define composite rules: injection + network = implant, credential access + network = exfiltration
- Require corroboration for high-confidence kills (no single-signal kills)

#### 8. Fix Parent-Child Detection
- Actually implement the `SuspiciousParentChild` dictionary logic in WindowsMonitor
- Use `ProcessAncestryCache` (CreateToolhelp32Snapshot) for ancestry resolution
- Detect: Office → shell, Explorer → mshta/regsvr32/rundll32

---

### P2 — Medium Priority (v0.1.0 Milestone)

#### 9. Add File Activity Monitoring
- `FileSystemWatcher` on user profile, Downloads, temp directories
- Detect ransomware patterns (bulk renames, shadow copy deletion attempts)
- Monitor sensitive system files (hosts, SAM, etc.)

#### 10. Add Registry Persistence Detection (Windows)
- Poll HKLM/HKCU Run keys, scheduled tasks, services
- Baseline at startup, alert on changes
- Detect WMI event subscription persistence

#### 11. Implement Memory Scanning
- `VirtualQueryEx` to enumerate memory regions per-process
- Flag RWX regions in non-JIT processes
- Detect unbacked executable regions (process hollowing indicator)

#### 12. Add Connectivity Health Check
- Periodic canary request to known endpoint
- Detect if agent's network traffic is being blocked (EDRSilencer pattern)
- Alert and switch to hardened local-only detection if silenced

#### 13. Improve Self-Protection
- QPC-based timing to detect suspension (as Sentinel does)
- Service registry self-healing via native SCM P/Invoke
- Binary integrity on configurable interval (already have SHA-256 baseline)
- Block config changes from non-SYSTEM processes

---

### P3 — Lower Priority (Future Roadmap)

#### 14. Add DPAPI Key Protection (Windows)
- Wrap machine key with `ProtectedData.Protect(scope: LocalMachine)`
- Incorporate installation entropy into HMAC derivation
- Bind key to boot nonce to prevent cross-boot replay

#### 15. Linux: Add eBPF/fanotify Integration
- Replace /proc polling with eBPF program for real-time process/file/network events
- Use fanotify for file access monitoring
- Subscribe to auditd netlink socket for real-time audit events

#### 16. Add Telemetry Fusion Layer
- Per-process event chains with temporal ordering
- Cross-source enrichment (process + network + file = context)
- Event graph for incident timeline reconstruction

#### 17. Implement Active Deception
- Deploy credential canaries (Windows Credential Manager, /etc/shadow entries)
- Deploy canary files in high-value directories
- Optional: fake service listeners as lateral movement traps

#### 18. Add SecurityValidation Utility Class
- Centralized input validation (paths, filenames, IPs, PIDs, ports)
- Consistent across all components (port from Sentinel's `SecurityValidation.cs`)
- Includes Windows reserved name checking, private IP detection, path containment

---

## DESIGN PRINCIPLES TO ADOPT FROM SENTINEL

1. **Behavioral over static** — Detect what processes DO (API calls, memory operations, network activity), not what they ARE (process name, hash). Process names are metadata enrichment, never detection triggers.

2. **No single-signal kills** — Require corroboration from different data sources before automated response. One weak signal should never trigger a kill (except self-protection).

3. **Tiered detection** — Tier1 rules can authorize response. Tier2 rules only log and feed correlation. This prevents false positives from causing damage.

4. **Assume the attacker reads the code** — No security-by-obscurity. Detection must work even when adversary knows all rule logic.

5. **Graceful degradation** — When ETW isn't available, fall back to WMI/polling. When network is silenced, switch to local-only hardened mode. Never crash on degraded capability.

6. **President's Law (Closed Kill List)** — Only explicitly enumerated behaviors authorize automated process termination. New rules default to log-only. This prevents scope creep in response authority.

7. **Self-protection is non-negotiable** — In Release builds, self-protection cannot be disabled via config. If attacker tampers config, they must not be able to disable the protections that would detect them.

8. **Monitor groups with priority** — Critical self-protection monitors start first and restart indefinitely. Lower-priority monitors have limited restart budgets. Prevents thundering herd at startup.

---

## CODE-LEVEL FINDINGS

### Finding 1: Unused SuspiciousParentChild Dictionary (Bug)

**File:** `src/Behavedr.Core/Monitors/WindowsMonitor.cs`

The `SuspiciousParentChild` dictionary is defined but never referenced anywhere in the detection logic. This appears to be dead code from an incomplete implementation.

```csharp
// This dictionary is defined but NEVER USED in GetSignalsAsync()
private static readonly Dictionary<string, HashSet<string>> SuspiciousParentChild = new(...)
{
    ["winword"] = new(...) { "cmd", "powershell", "pwsh", ... },
    ...
};
```

**Recommendation:** Implement parent-child checking or remove the dead code to avoid false confidence.

---

### Finding 2: Short-Lived PowerShell Detection is Unreliable

**File:** `src/Behavedr.Core/Monitors/WindowsMonitor.cs`

```csharp
var runTime = DateTime.Now - startTime;
if (runTime.TotalSeconds < 3)
{
    signals.Add(new Signal("short_lived_powershell", 40, 0.6));
}
```

**Issue:** This checks currently-running PowerShell processes. If PowerShell exits in <3s, it will already be gone by the time the 5-second polling cycle runs. This detection only fires if the scan happens to run during the 0-3s window — an unlikely coincidence.

---

### Finding 3: Process Burst Detection Races with Scan Interval

**File:** `src/Behavedr.Core/Monitors/WindowsMonitor.cs`

```csharp
var recentThreshold = DateTime.Now.AddSeconds(-10);
// counts processes started in last 10 seconds
if (recentCount > 20) { /* signal */ }
```

**Issue:** With a 5-second scan interval, this detection may fire multiple times for the same burst (counts overlap between scans) or miss bursts that happen between scans and whose processes exit quickly.

---

### Finding 4: DetectionEvent.Score Field Unused

**File:** `src/Behavedr.Core/Models/DetectionEvent.cs`

```csharp
public record DetectionEvent(..., double Score, ...);
```

The `Score` field in `DetectionEvent` is always passed as `0.0` via `DetectionEvent.Create()` and is never used by the scoring engine (which calculates its own score from signals). This is confusing dead state.

---

### Finding 5: Synchronous ProcessEvent Anti-Pattern

**File:** `src/Behavedr.Core/DetectionEngine.cs`

```csharp
public DetectionResult ProcessEvent(DetectionEvent evt)
{
    return ProcessEventAsync(evt, CancellationToken.None).GetAwaiter().GetResult();
}
```

**Issue:** Sync-over-async can cause deadlocks in certain synchronization contexts. Mark as `[Obsolete]` and remove callers.

---

## COMPARISON MATRIX: Behavedr vs Sentinel

| Capability | Behavedr v0.0.6 | Sentinel v1.5.4 |
|---|---|---|
| **Platforms** | Windows, Linux, macOS, Android, iOS | Windows only |
| **Detection latency** | 5000ms (polling) | ~50ms (ETW) |
| **Process monitoring** | Process.GetProcesses() name matching | ETW Kernel-Process + WMI fallback |
| **Network monitoring** | None | GetExtendedTcpTable + DNS ETW + BeaconingDetector |
| **Memory analysis** | None | VirtualQueryEx + shellcode pattern + RWX detection |
| **File monitoring** | None (quarantine only) | FileSystemWatcher + ETW Kernel-File |
| **Registry monitoring** | None | ETW Kernel-Registry + persistence key polling |
| **Credential protection** | None | Chrome/Firefox/MS Account guards + LSASS canary |
| **Injection detection** | None | ETW Threat-Intelligence (kernel-level API observation) |
| **Parent-child analysis** | Defined but unused | ProcessAncestryCache + PPID spoof detection |
| **Behavioral correlation** | None (flat scoring) | 120s sliding window + 10 composite rules |
| **Detection tiers** | Single score threshold | Tier1 (kill) + Tier2 (corroborate) |
| **Self-protection** | Debugger check + binary hash | Anti-tamper (suspend/terminate/service heal) + watchdog |
| **Deception** | None | Credential canary + file canary + active deception suite |
| **Anti-tamper** | Basic | QPC timing + handle protection + service self-heal + WFP guard |
| **Update signing** | Placeholder (bypassed) | N/A (no auto-update) |
| **Config protection** | HMAC-SHA256 seal | SHA-256 baseline + runtime tamper detection |
| **Communication security** | mTLS + cert pinning + fail-closed | HMAC-signed telemetry to proxy |
| **Offline resilience** | AES-256-GCM encrypted buffer | N/A (local detection only) |
| **Metrics/telemetry** | OpenTelemetry counters + histograms | SentinelMetrics (P50/P90/P95/P99 histograms) |
| **Test coverage** | 49 tests | 367 tests |
| **Monitor count** | 3 (Windows, Linux, Android) | 70+ specialized monitors |

---

## WHAT BEHAVEDR HAS THAT SENTINEL DOESN'T

Behavedr has legitimate architectural advantages to preserve:

1. **Multi-platform support** — Linux, macOS, Android, iOS coverage is unique. Sentinel is Windows-only by design constraint.

2. **Agent-server communication** — mTLS client certs, encrypted offline buffering, policy distribution. Sentinel operates purely locally with no server communication.

3. **Encrypted offline buffer** — AES-256-GCM encrypted reports survive network outages and resist forensic extraction. Sentinel has no equivalent.

4. **Auto-update mechanism** — Self-updating agent infrastructure (once signing key is real). Sentinel requires manual update.

5. **OpenTelemetry metrics** — Standard OTel counters/histograms exportable to Prometheus/OTLP. Sentinel has custom metrics.

6. **Centralized policy management** — Server can push scoring config, response policy, monitoring intervals. Sentinel has local-only config.

7. **Cross-platform detection engine** — Shared `Behavedr.Core` between desktop and mobile. Same scoring/response logic everywhere.

---

## IMPLEMENTATION ROADMAP (Suggested)

```
v0.0.7 — Security Critical
├── Replace placeholder signing key (RT-1)
├── Add parent-child process detection (actually use the existing dictionary)
├── Add command-line argument scanning (encoded PS, LOLBins, download cradles)
└── Add connectivity health canary

v0.0.8 — Windows Detection Maturity
├── NetworkMonitor (GetExtendedTcpTable/GetExtendedUdpTable P/Invoke)
├── FileActivityMonitor (FileSystemWatcher on user profile + Downloads)
├── Basic beaconing detection (interval CV analysis)
└── ScheduledTaskMonitor (schtasks parsing)

v0.0.9 — ETW Integration
├── UnifiedEtwSession (Kernel-Process, Kernel-File, DNS-Client)
├── ETW Threat-Intelligence for injection detection
├── Real-time process creation monitoring
└── Graceful degradation when ETW unavailable

v0.1.0 — Behavioral Correlation
├── BehavioralCorrelationEngine (120s sliding window)
├── Tiered detection model (Tier1 kill-authorized, Tier2 log-only)
├── Composite detection rules
├── ProcessAncestryCache
└── Memory analysis (VirtualQueryEx + RWX detection)

v0.2.0 — Self-Protection & Deception
├── AntiTamperGuard (QPC timing, handle protection, service self-heal)
├── Watchdog process (mutual monitoring)
├── CredentialCanaryMonitor
├── ChromeCredentialGuardMonitor
└── WFP integrity monitoring
```

---

## CONCLUSION

Behavedr has a solid **foundation** — the cryptographic primitives, communication security, and architectural patterns are well-designed. The multi-platform ambition and agent-server model give it capabilities Sentinel doesn't have.

However, the **detection surface is critically underdeveloped**. The current implementation detects almost nothing a real attacker would do. The three most impactful improvements are:

1. **ETW integration** — transforms the agent from blind (5s polling snapshots) to real-time kernel visibility
2. **Behavioral detection** — move from "is this named mimikatz?" to "is this process injecting code into another?"
3. **Anti-tamper hardening** — an attacker who can `taskkill` the EDR has won; this must be prevented

The Sentinel codebase provides a comprehensive reference implementation for Windows-specific detection. Its key lesson: **detect behaviors, not names; correlate signals, don't score in isolation; and protect yourself before protecting others.**

---

*This audit assumes the attacker has read the source code. No security-by-obscurity.*
