# Behavedr EDR — Red/Blue Team Security Audit + Sentinel Cross-Reference

**Date:** 2026-07-21
**Version Audited:** 0.1.0
**Auditor:** AI-assisted security analysis
**Scope:** Full source code review, architecture analysis, evasion modeling, cross-reference with Sentinel EDR
**Sentinel Version:** Latest (Windows-only EDR, 60+ monitors)

---

## Executive Summary

Behavedr v0.1.0 represents a **mature, well-hardened behavioral EDR** with strong
cryptographic foundations, fail-closed communications, and genuine defense-in-depth
on Windows. The previous v0.0.9 audit's P0/P1 findings have been addressed:

- PID-scoped behavioral correlation (eliminates cross-process false positives)
- Native ETW payload parsing (ProcessName, ParentPID, CommandLine from events)
- Per-installation random DPAPI entropy (not hardcoded)
- Data exfiltration byte counters via GetPerTcpConnectionEStats
- Process DACL protection via SetSecurityInfo

**However**, cross-referencing against the Sentinel EDR reveals **15+ detection gaps**
where Behavedr has zero coverage for attacks that Sentinel actively detects. These
represent the highest-value improvement opportunities for the next release cycle.

---

## RED TEAM ANALYSIS — Attack Surfaces (v0.1.0)

### RT-1: No DLL Sideloading Detection (HIGH)

**Attack:** Drop a malicious `version.dll` or `dbghelp.dll` into the same directory as a
legitimate application. Windows DLL search order loads the local copy instead of System32.

**Current State:** Behavedr has zero visibility into loaded module lists. No detection for
system DLLs loaded from non-system paths. No remediation capability.

**Sentinel Comparison:** Sentinel's `DllUnloadEngine` enumerates loaded modules per process,
detects sideloaded system DLLs, quarantines them (XOR-encrypted), places lock files to
prevent re-drop, and can unload DLLs from live processes via QueueUserAPC + FreeLibrary.

**Impact:** Complete bypass. Attacker achieves code execution inside a legitimate process
with no detection signal generated.

**Recommendation:** Import DLL sideloading detection. Core logic:
1. Enumerate `Process.Modules` for running processes
2. Check if known system DLLs are loaded from non-Windows directories
3. Kill compromised process + quarantine sideloaded DLL
4. Place zero-byte read-only lock file at original path

---

### RT-2: No LSASS Credential Dump Detection (HIGH)

**Attack:** Mimikatz, comsvcs.dll MiniDump, or direct `NtReadVirtualMemory` against LSASS
to extract credentials. This is the #1 post-exploitation technique.

**Current State:** Behavedr's `CredentialGuardMonitor` watches for non-browser SQLite loading
(browser credential theft). The `CredentialCanaryMonitor` catches credential manager
enumeration. But **LSASS memory access is completely unmonitored**.

**Sentinel Comparison:** `LsassDumpCanaryMonitor` provides triple-source detection:
- Sysmon Event ID 10 (ProcessAccess) with PROCESS_VM_READ to lsass.exe
- Security Event ID 4656/4663 (handle to LSASS with read permissions)
- Defender ASR Event ID 1121 (credential theft rule triggered)
Trust is path+signature verified, never name-only.

**Impact:** Attacker can dump all domain credentials from LSASS with zero alerts.

**Recommendation:** Implement Sysmon/Security event log monitoring for LSASS access patterns.
Priority: P0 — this is the most common post-exploitation technique in enterprise attacks.

---

### RT-3: No Parent PID Spoofing Detection (HIGH)

**Attack:** Use `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` in `CreateProcess` to spoof the
parent PID. This defeats parent-child analysis (Behavedr's core behavioral detection).

**Current State:** `BehavioralMonitor` relies entirely on parent-child relationships.
If an attacker spawns `cmd.exe` with a spoofed parent of `explorer.exe`, the
"suspicious_parent_child" detection is completely bypassed.

**Sentinel Comparison:** `ParentPidSpoofDetector` calls `NtQueryInformationProcess` to get
the kernel-reported `InheritedFromUniqueProcessId` and compares it against the ETW-recorded
creator PID in the ancestry cache. Mismatch = PPID spoofing (T1134.004).

**Impact:** Attacker bypasses all parent-child behavioral detections — the largest
signal source in Behavedr's detection stack.

**Recommendation:** Add PPID spoofing detection:
1. Query `PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId` via NtQueryInformationProcess
2. Compare against `ProcessAncestryCache` recorded parent
3. Mismatch (excluding system processes) = high-confidence detection

---

### RT-4: No Ghost Process / Process Hollowing Detection (HIGH)

**Attack:** Process hollowing (T1055.012) — create a legitimate process suspended, unmap
its image, map malicious code, resume. The process runs under a trusted name but executes
attacker code. Network connections persist under the hollowed PID.

**Current State:** Behavedr's `SelfProtectionService` checks its own type resolution (basic
hollowing self-check), but has **no visibility into other processes being hollowed**.
The `MemoryAnalyzer` checks for RWX regions but not image path mismatches.

**Sentinel Comparison:** Two complementary monitors:
- `GhostProcessMonitor`: Detects PIDs with active outbound connections that cannot be
  resolved to a running process (orphaned sockets from hollowed/exited processes)
- `MemoryBehaviorAnalyzer`: Tracks module count growth over time (injection indicator)
  and compares MainModule path against expected image for the process name

**Impact:** Complete EDR bypass. Attacker code runs under a trusted process name,
bypasses all name-based and parent-child behavioral checks.

**Recommendation:** Implement ghost process detection:
1. Periodically enumerate established outbound TCP connections (GetExtendedTcpTable)
2. Attempt to resolve each owning PID to a valid, named process
3. Unresolvable PIDs or empty-name processes with active connections = high confidence alert

---

### RT-5: No Token Integrity / Privilege Escalation Detection (MEDIUM-HIGH)

**Attack:** UAC bypass or privilege escalation results in elevated processes running from
user-writable directories (Temp, Downloads, AppData). Legitimate elevated processes
run from Program Files or System32.

**Current State:** No token or integrity level monitoring.

**Sentinel Comparison:** `TokenIntegrityMonitor` calls `OpenProcessToken` + `GetTokenInformation`
(TOKEN_ELEVATION) on all processes, flagging elevated processes whose image path is in
a user-writable directory.

**Impact:** UAC bypass goes completely undetected. Attacker achieves admin without any alert.

**Recommendation:** Implement elevation-from-user-path detection. Low implementation cost,
high detection value for UAC bypass techniques.

---

### RT-6: No Raw Disk Access Detection (MEDIUM-HIGH)

**Attack:** Open `\\.\PhysicalDrive0` or `\\.\C:` directly to read/write disk sectors.
Bypasses NTFS, file monitors, ADS verdicts, and all file-level protections.
Used for bootkit installation and forensic evidence destruction.

**Current State:** No detection. Behavedr monitors files via FileSystemWatcher which is
entirely bypassed by raw disk I/O.

**Sentinel Comparison:** `RawDiskAccessMonitor` enumerates process handles via
`NtQuerySystemInformation(SystemHandleInformation)`, duplicates handles to query object
names, and detects raw disk device paths. Dual-gated allowlist (path + Authenticode signature).

**Impact:** Attacker can plant bootkits, wipe forensic evidence, or exfiltrate data
below the filesystem abstraction with zero detection.

**Recommendation:** Implement raw disk handle scanning. Even a simplified version
(periodic scan of handle table for PhysicalDrive patterns) provides significant coverage.

---

### RT-7: No Ephemeral/Flash Process Detection (MEDIUM-HIGH)

**Attack:** Fast-acting malware that spawns, executes payload, and exits in <500ms.
Runs between ETW event delivery cycles, leaving no trace in process monitoring.

**Current State:** Native ETW provides ~50ms latency (good), but if the process exits
before the next `DrainProcessEvents()` call in `MonitoringService`, the command line
is captured but no behavioral analysis runs against it.

**Sentinel Comparison:** `EphemeralProcessMonitor` watches the Windows Prefetch directory
(`C:\Windows\Prefetch`) via FileSystemWatcher. Every executable that runs — even for
milliseconds — creates a .pf file. New .pf files that weren't in the startup baseline
indicate new process executions regardless of duration.

**Impact:** Fast droppers, credential dumpers, and exec-and-delete stagers go undetected.

**Recommendation:** Add Prefetch directory monitoring. Implementation is lightweight
(FileSystemWatcher + baseline hash set). Catches sub-second processes that ETW misses.

---

### RT-8: No Network Share / Lateral Movement Detection (MEDIUM-HIGH)

**Attack:** Attacker with valid credentials maps admin shares (C$, ADMIN$, IPC$) on remote
machines for lateral movement. Or creates unauthorized local shares to expose drives.

**Current State:** Zero SMB monitoring. `NetworkConnectionMonitor` tracks ports and
connection counts but has no concept of share activity.

**Sentinel Comparison:** `NetworkShareMonitor` provides:
- Runtime share mapping detection (new mappings after baseline)
- Admin share access monitoring (C$, ADMIN$, IPC$)
- Inbound SMB session detection (NetSessionEnum)
- Unauthorized local share creation (auto-deletes malicious shares)

**Impact:** Complete blind spot for the most common enterprise lateral movement technique.

**Recommendation:** Implement SMB/share monitoring. Start with:
1. Baseline mapped drives at startup, alert on new mappings
2. Monitor admin share access via NetFileEnum
3. Detect new local share creation via NetShareEnum delta

---

### RT-9: No WSL Attack Surface Monitoring (MEDIUM)

**Attack:** Execute Linux-native attack tools inside WSL2 (netcat, reverse shells, nmap).
WSL has direct filesystem access to Windows via `/mnt/c/`. Security tools with no WSL
visibility are completely blind to this attack surface.

**Current State:** No WSL monitoring.

**Sentinel Comparison:** `WslMonitor` tracks WSL process spawns, monitors command lines
for suspicious patterns (reverse shells, credential access), detects runtime distro
installation, and flags processes loaded from `\\wsl$` filesystem.

**Impact:** Attacker operates from WSL with full Windows filesystem access and zero detection.

**Recommendation:** Monitor `wsl.exe`/`wslhost.exe` process creation and command lines.
Detect runtime `wsl --import` for new distribution installation.

---

### RT-10: No Unmapped Thread Start Address Detection (MEDIUM)

**Attack:** Reflective DLL injection, shellcode injection, or direct syscall execution.
Threads start at addresses that don't map to any loaded DLL/executable on disk.

**Current State:** `MemoryAnalyzer` scans for RWX memory regions (good for shellcode detection)
but doesn't check where threads actually START executing from.

**Sentinel Comparison:** `EtwThreatIntelMonitor` enumerates `ProcessThread.StartAddress`
for all threads, builds loaded module address ranges, and flags threads starting outside
any mapped image. Classic indicator of injection/shellcode.

**Impact:** Sophisticated injection that doesn't leave RWX regions (direct syscall, ROP
gadgets in existing modules) bypasses Behavedr's memory analysis.

**Recommendation:** Add thread start address scanning as a complement to RWX detection.
The combination of RWX + unmapped start address provides comprehensive injection coverage.

---

### RT-11: No Ransomware-Specific I/O Pattern Detection (MEDIUM)

**Attack:** Ransomware encrypts files by mass-renaming with new extensions (50+ files/5s).

**Current State:** `FileActivityMonitor` detects ransomware-like rename bursts, but it
uses a simpler threshold approach. No per-PID tracking with verified allowlist.

**Sentinel Comparison:** `RansomwareIoMonitor` tracks renames per-PID with a verified
allowlist (name + path verification to prevent bypass-by-renaming). 50+ renames in
5 seconds from a single non-allowlisted process = immediate process tree kill.

**Impact:** Existing detection may work but with higher false positive rate from browsers/IDEs.

**Recommendation:** Adopt Sentinel's per-PID rename tracking with path-verified allowlist.

---

### RT-12: No Attack Chain Tracing (MEDIUM)

**Attack:** After detection, only the immediate malicious process is killed. The attacker's
persistence mechanisms, parent processes, and dropped binaries remain active.

**Current State:** `ProcessKillAction` kills the detected process (with tree kill). But
there is no ancestor walking, no persistence cleanup, no binary quarantine along the chain.

**Sentinel Comparison:** `ChainTracer` walks the full parent chain, identifies the attack
root (first non-system binary), kills all chain processes, quarantines non-system binaries,
and removes persistence (Run keys, scheduled tasks).

**Impact:** Attacker retains persistence and can re-establish access after the killed process
is gone. Kill-only response is necessary but not sufficient.

**Recommendation:** Implement chain tracing for Tier1 detections:
1. Walk parent chain via ProcessAncestryCache
2. Identify attack root
3. Kill all non-system processes in chain
4. Remove Run key entries associated with chain binaries
5. Quarantine non-system executables in the chain

---

### RT-13: No Isolation Environment Response (MEDIUM)

**Attack:** Malware delivered via mounted ISO images (bypasses Mark-of-the-Web),
Docker containers, or VMs. These isolation layers prevent host AV inspection until
execution begins.

**Current State:** No awareness of ISO mounts, container execution, or VM-hosted threats.

**Sentinel Comparison:** `IsolationResponseEngine` handles:
- ISO threats: kill process + dismount ISO + delete .iso file
- Docker threats: stop container + remove + delete image
- VM threats: terminate VM host process (graceful Hyper-V stop via WMI or forced kill)

**Impact:** Attacker distributes malware in ISO files (common in phishing campaigns since
Windows 11 blocks macros). Even if detected behaviorally, the ISO remains mounted and
accessible for re-execution.

**Recommendation:** At minimum, implement ISO mount awareness. When a malicious process
is detected running from a mounted ISO drive letter, dismount the ISO and delete the source.

---

### RT-14: No PseudoSandbox / Containment Capability (LOW-MEDIUM)

**Attack:** Suspicious but not yet confirmed malicious process runs with full system access.

**Current State:** Binary decision — either alert-only or kill. No middle ground.

**Sentinel Comparison:** `PseudoSandbox` spawns suspicious processes inside Windows Job
Objects with strict limits: 64MB memory, idle CPU priority, max 3 child processes,
UI/clipboard restrictions, no admin privileges. Monitors for 5 seconds, kills on violation.

**Impact:** Behavedr must choose between false-positive kills and missed detections.
A sandbox layer allows observing ambiguous processes under constraints.

**Recommendation:** Future enhancement. Job Object containment is powerful but complex.
Consider for v0.2.0+ roadmap.

---

### RT-15: No Authenticode / Code Signing Verification (LOW-MEDIUM)

**Attack:** Attacker renames malware to match allowlisted process names. Name-only
allowlists are trivially bypassed.

**Current State:** Behavedr's `ProcessKillAction` uses a name-only protected process list.
No signature verification. An attacker naming malware "explorer.exe" in a temp directory
would be protected from being killed.

**Sentinel Comparison:** `SignerTrustService` provides Authenticode signature verification
with write-time cache invalidation. Allowlist exemptions require both name match AND
valid signature from a trusted path. Signed status reduces confidence but never grants immunity.

**Impact:** Name-only allowlists in ProcessKillAction and other monitors are bypassable.

**Recommendation:** Implement Authenticode verification for trust decisions. At minimum,
verify image path for protected process list (is it actually from System32?).

---

## RED TEAM SUMMARY TABLE (v0.1.0)

| # | Gap | Severity | MITRE ATT&CK | Sentinel Has It? | Import Priority |
|---|-----|----------|--------------|-------------------|-----------------|
| RT-1 | No DLL sideloading detection | HIGH | T1574.001 | Yes (DllUnloadEngine) | P0 |
| RT-2 | No LSASS credential dump detection | HIGH | T1003.001 | Yes (LsassDumpCanaryMonitor) | P0 |
| RT-3 | No PPID spoofing detection | HIGH | T1134.004 | Yes (ParentPidSpoofDetector) | P0 |
| RT-4 | No ghost process / hollowing detection | HIGH | T1055.012 | Yes (GhostProcessMonitor) | P1 |
| RT-5 | No token/privilege escalation detection | MEDIUM-HIGH | T1548 | Yes (TokenIntegrityMonitor) | P1 |
| RT-6 | No raw disk access detection | MEDIUM-HIGH | T1006 | Yes (RawDiskAccessMonitor) | P1 |
| RT-7 | No ephemeral process detection | MEDIUM-HIGH | T1059 | Yes (EphemeralProcessMonitor) | P1 |
| RT-8 | No SMB/lateral movement detection | MEDIUM-HIGH | T1021.002 | Yes (NetworkShareMonitor) | P1 |
| RT-9 | No WSL attack surface monitoring | MEDIUM | T1202 | Yes (WslMonitor) | P2 |
| RT-10 | No unmapped thread start detection | MEDIUM | T1055 | Yes (EtwThreatIntelMonitor) | P2 |
| RT-11 | No ransomware I/O per-PID tracking | MEDIUM | T1486 | Yes (RansomwareIoMonitor) | P2 |
| RT-12 | No attack chain tracing | MEDIUM | Multiple | Yes (ChainTracer) | P2 |
| RT-13 | No isolation environment response | MEDIUM | T1553.005 | Yes (IsolationResponseEngine) | P2 |
| RT-14 | No sandbox containment | LOW-MEDIUM | N/A | Yes (PseudoSandbox) | P3 |
| RT-15 | No code signing verification | LOW-MEDIUM | T1036.005 | Yes (SignerTrustService) | P2 |

---

## BLUE TEAM ANALYSIS — Defensive Strengths (v0.1.0)

### S1: Cryptographic Architecture (EXCELLENT)

The cryptographic stack is the strongest aspect of Behavedr and **superior to Sentinel**:

| Capability | Behavedr | Sentinel |
|-----------|----------|----------|
| Key wrapping | DPAPI + per-install entropy | None (raw file) |
| Config integrity | HMAC-SHA256 (timing-safe) | None |
| Data at rest | AES-256-GCM (SecureEnvelope) | None |
| Update signing | RSA-4096 PSS | None |
| Communication | mTLS + cert pinning (fail-closed) | HTTPS only |
| Key derivation | HKDF purpose-separated | N/A |
| Legacy migration | AES-CBC backward compat | N/A |

Behavedr's crypto is enterprise-grade and correctly implemented. No custom primitives.
HKDF purpose separation means compromising one key doesn't expose others.

---

### S2: Communication Security (EXCELLENT)

- **Fail-closed design:** No CA cert configured = ALL connections rejected (not insecure fallback)
- **mTLS:** Client certificate required for agent authentication
- **Certificate pinning:** Custom root trust, no system CA fallback
- **Policy verification:** RSA-PSS signature on policy updates before acceptance
- **Replay prevention:** Per-report nonce + monotonic sequence + per-boot nonce
- **Offline resilience:** Encrypted at-rest buffer with authenticated replay on reconnection
- **Query injection prevention:** `Uri.EscapeDataString` on all parameters

This is significantly more hardened than Sentinel's plain HTTPS communication.

---

### S3: Supply Chain Hardening (EXCELLENT)

- GitHub Actions pinned to **commit SHAs** (not tags)
- `<Deterministic>true</Deterministic>` reproducible builds
- `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` pinned dependencies
- `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`
- SBOM generation
- Single-file deployment (no temp extraction)
- NuGet lock files committed

This exceeds Sentinel's supply chain practices.

---

### S4: Self-Protection (STRONG)

| Mechanism | Status |
|-----------|--------|
| Process DACL (deny PROCESS_TERMINATE) | Implemented via SetSecurityInfo |
| QPC suspension detection | 4-second threshold, hardware-backed |
| Binary integrity (SHA-256 baseline) | Dual implementation (SelfProtection + AntiTamper) |
| Anti-debug (Debugger.IsAttached) | FailFast in Release, warn in Debug |
| Process hollowing self-check | Type resolution verification |
| Service re-registration | Registry self-healing |
| Config lock in Release | Self-protection cannot be disabled |
| Watchdog heartbeat | 15s staleness detection |
| Last-gasp forensics | AppDomain.UnhandledException + ProcessExit |
| Connectivity canary | EDRSilencer/WFP network blocking detection |

---

### S5: Behavioral Correlation (STRONG — improved from v0.0.9)

The v0.1.0 correlation engine is now **PID-scoped**, addressing the critical v0.0.9
false positive issue (RT-9 from previous audit). Composite rules require signals from
the same PID or process tree:

- Injection + Network (same PID) → "In-Memory Implant Active" (0.96)
- Credential Access + Network (same PID) → "Credential Theft + Exfil" (0.95)
- Parent-Child + Encoded PS (same PID) → "Fileless Attack Chain" (0.94)
- Anti-Tamper is correctly scoped as system-wide (not PID-specific)

---

### S6: Signal Quality (STRONG)

- **Deduplication:** Per-type cooldown (30s), composite cooldown (120s)
- **Exponential decay:** Older signals fade via `weight * e^(-lambda*t)`
- **Score fidelity:** Raw scores preserved (not hard-clamped to 100)
- **Severity tiers:** Info/Low/Medium/High/Critical/Extreme based on raw score
- **Command-line normalization:** Defeats caret, env-var, tick evasion

---

### S7: Multi-Platform Architecture (GOOD — Windows strong, others weak)

- **Windows:** 15+ active monitors, native ETW, full behavioral analysis
- **Linux:** Real implementation but polling-based (no eBPF/fanotify)
- **macOS/iOS:** Stubs only — not production-ready
- **Android:** Signal injection API (depends on companion app)

The cross-platform architecture is correctly abstracted via `IPlatformMonitor`, making
it easy to add platform-specific implementations without changing the core engine.

---

## SENTINEL CROSS-REFERENCE — Importable Capabilities

### Priority 0 (Critical — import immediately)

| Sentinel Component | What It Does | Effort | Impact |
|-------------------|-------------|--------|--------|
| LsassDumpCanaryMonitor | Sysmon/Security event log monitoring for LSASS access | Medium | Closes #1 credential theft gap |
| ParentPidSpoofDetector | NtQueryInformationProcess PPID vs ETW ancestry comparison | Low | Closes bypass of parent-child analysis |
| DllUnloadEngine (detection only) | Enumerate Process.Modules for sideloaded system DLLs | Medium | Closes DLL sideloading blind spot |

### Priority 1 (High — next release cycle)

| Sentinel Component | What It Does | Effort | Impact |
|-------------------|-------------|--------|--------|
| GhostProcessMonitor | PIDs with network but no resolvable process | Low | Catches hollowed/exited RATs |
| TokenIntegrityMonitor | Elevated processes from user-writable paths | Low | Catches UAC bypass |
| RawDiskAccessMonitor | NtQuerySystemInformation handle enumeration | High | Catches bootkits + forensic wiping |
| EphemeralProcessMonitor | Prefetch directory watching for flash payloads | Low | Catches sub-second stagers |
| NetworkShareMonitor | SMB session/share/file monitoring | Medium | Catches lateral movement |

### Priority 2 (Medium — roadmap items)

| Sentinel Component | What It Does | Effort | Impact |
|-------------------|-------------|--------|--------|
| EtwThreatIntelMonitor | Thread start address vs module range scanning | Medium | Catches reflective injection |
| WslMonitor | WSL process/command/filesystem monitoring | Low | Covers WSL attack surface |
| ChainTracer | Full parent chain kill + persistence cleanup | Medium | Comprehensive response |
| SignerTrustService | Authenticode verification for trust decisions | Medium | Hardens allowlists |
| IsolationResponseEngine | ISO dismount + Docker kill + VM terminate | Medium | Handles container escapes |
| RansomwareIoMonitor (improved) | Per-PID rename tracking with path-verified allowlist | Low | Reduces FP in ransomware detection |

### Priority 3 (Future — complex features)

| Sentinel Component | What It Does | Effort | Impact |
|-------------------|-------------|--------|--------|
| PseudoSandbox | Windows Job Object containment | High | Graduated response model |
| ContextBus | Cross-monitor signal publishing | Medium | Richer correlations |
| TelemetryFusionEngine | Multi-source signal fusion | High | Unified threat view |

---

## ARCHITECTURAL RECOMMENDATIONS FROM SENTINEL

### 1. ContextBus Pattern

Sentinel uses a `ContextBus` for inter-monitor communication. When one monitor detects
something, it publishes a signal that other monitors can consume for enrichment.

Example: `EtwThreatIntelMonitor` detects unmapped thread → publishes `InjectionSignal` →
`DllUnloadEngine` consumes it and scans the target process for sideloaded DLLs →
`GhostProcessMonitor` adds the PID to heightened watch.

**Recommendation for Behavedr:** The current architecture passes signals through the
`DetectionEngine` → `BehavioralCorrelationEngine` pipeline. Consider adding a lightweight
pub/sub bus for real-time cross-monitor enrichment without going through the full
detection cycle.

### 2. Detection Tiers

Sentinel classifies detections into:
- **Tier1Behavioral:** High confidence, automated response authorized
- **Tier2Indicator:** Lower confidence, log-only or human review

Behavedr uses raw scores + `PresidentKill` threshold, which is functionally equivalent
but less semantically clear. The tier model is useful for documentation and policy.

### 3. Structured Event Logging (JSONL)

Sentinel's `JsonlEventLogger` writes all detection and response events as structured
JSON lines to rotating log files. This provides:
- Machine-parseable forensic evidence
- SIEM integration without custom parsing
- Offline investigation capability

Behavedr uses Serilog (good), but structured detection events with fixed schemas would
improve forensic and integration capabilities.

### 4. SignerTrustService with Cache Invalidation

Sentinel caches Authenticode verification results per file path but **invalidates on
LastWriteTime change**. This prevents an attacker from signing a binary, letting it get
cached as "trusted", then replacing it with malware.

This pattern should be adopted for any future allowlist or trust verification in Behavedr.

---

## RESIDUAL STRENGTHS — Where Behavedr Exceeds Sentinel

Despite the detection gaps, Behavedr has significant architectural advantages:

| Area | Behavedr Advantage |
|------|-------------------|
| Crypto | DPAPI + HKDF + AES-GCM + RSA-PSS vs. nothing in Sentinel |
| Communication | mTLS + cert pinning + fail-closed vs. plain HTTPS |
| Supply chain | SHA-pinned GH Actions + deterministic builds + SBOM |
| Cross-platform | Linux/macOS/Android architecture vs. Windows-only |
| Config protection | HMAC-sealed config + pre-seal validation + DPAPI |
| Update security | RSA-4096 PSS signature + Zip Slip protection |
| Offline resilience | Encrypted buffer with authenticated replay |
| Build hardening | TreatWarningsAsErrors + lock files + single-file deploy |

**Sentinel has zero cryptographic infrastructure.** Its offline buffer is unencrypted,
its config is plain JSON, its updates have no signature verification, and its
communication is standard HTTPS without certificate pinning. In a supply chain attack
or MITM scenario, Behavedr is significantly more resilient.

---

## COMBINED REMEDIATION ROADMAP

### v0.2.0 (Next Release — P0 fixes)

1. **LsassDumpMonitor** — Sysmon Event ID 10 + Security Event ID 4656 monitoring
2. **ParentPidSpoofDetector** — NtQueryInformationProcess comparison
3. **DllSideloadDetector** — Process.Modules enumeration for system DLLs in non-system paths
4. **ProcessKillAction hardening** — Verify image path for protected process list

### v0.3.0 (P1 features)

5. **GhostProcessMonitor** — Unresolvable PIDs with active network connections
6. **TokenIntegrityMonitor** — Elevated processes from user-writable paths
7. **EphemeralProcessMonitor** — Prefetch directory watching
8. **NetworkShareMonitor** — SMB lateral movement detection
9. **RawDiskAccessMonitor** — Handle scanning for raw device paths

### v0.4.0 (P2 features)

10. **ThreadStartAddressScanner** — Unmapped thread detection
11. **WslMonitor** — WSL process and command monitoring
12. **ChainTracer** — Full attack chain response
13. **SignerTrustService** — Authenticode verification for trust decisions
14. **IsolationResponseEngine** — ISO/Docker/VM threat handling
15. **RansomwareIoMonitor enhancement** — Per-PID + path-verified allowlist

### v0.5.0+ (P3 + architectural)

16. **ContextBus** — Cross-monitor signal publishing
17. **PseudoSandbox** — Windows Job Object containment
18. **JSONL structured event logging** — Machine-parseable forensic events
19. **ELAM/PPL investigation** — Kernel-level protection (requires MS signing)
20. **eBPF Linux monitor** — Real-time process visibility on Linux

---

## CONCLUSION

Behavedr v0.1.0 is a **solid cryptographic and communication foundation** with genuine
behavioral detection capabilities. Its strengths are in areas Sentinel completely ignores:
crypto, comms security, supply chain, and cross-platform architecture.

However, from a pure **detection coverage** perspective, Sentinel covers 15+ attack
techniques that Behavedr has zero visibility into. The most critical gaps are:
- LSASS credential dumping (P0)
- PPID spoofing bypassing parent-child analysis (P0)
- DLL sideloading (P0)
- Process hollowing / ghost processes (P1)
- Privilege escalation from user paths (P1)

The recommended path is to import Sentinel's detection logic while preserving Behavedr's
superior security architecture. The two projects are complementary — Sentinel provides
breadth of detection; Behavedr provides depth of security hardening.

---

*End of audit.*
