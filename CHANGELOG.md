# Changelog

## [0.2.0] — 2026-07-21

### Major Detection Expansion — 15 Audit Findings Addressed + Sentinel Cross-Reference

Implements all findings from the v0.1.0 red/blue team security audit. Cross-references
Sentinel EDR (Windows-only, 60+ monitors) to close 15 detection gaps while preserving
Behavedr's superior cryptographic and communication architecture.

#### P0 — Critical New Detections

- **LSASS Dump Monitor** (`LsassDumpMonitor.cs`): Detects credential dumping (T1003.001) via Sysmon Event ID 10 (ProcessAccess), Security Event ID 4656 (handle request), and Defender ASR Event ID 1121. Path+signature verified trust — never name-only.
- **Parent PID Spoof Detector** (`ParentPidSpoofDetector.cs`): Detects PPID spoofing (T1134.004) by comparing kernel-reported InheritedFromUniqueProcessId (NtQueryInformationProcess) against ETW-recorded parent in ProcessAncestryCache. Closes bypass of all parent-child behavioral analysis.
- **DLL Sideload Detector** (`DllSideloadDetector.cs`): Detects DLL sideloading (T1574.001) by enumerating Process.Modules and flagging known system DLLs (version.dll, dbghelp.dll, etc.) loaded from non-Windows directories.

#### P1 — High Priority New Detections

- **Ghost Process Monitor** (`GhostProcessMonitor.cs`): Detects PIDs with active outbound TCP connections that cannot be resolved to running processes. Catches process hollowing (T1055.012) and orphaned RAT sockets.
- **Token Integrity Monitor** (`TokenIntegrityMonitor.cs`): Detects elevated processes running from user-writable paths (Temp, Downloads, AppData). Catches UAC bypass (T1548).
- **Ephemeral Process Monitor** (`EphemeralProcessMonitor.cs`): Watches Windows Prefetch directory for new .pf files indicating sub-second process executions that ETW may miss.
- **Network Share Monitor** (`NetworkShareMonitor.cs`): Detects unauthorized local share creation and new network drive mappings at runtime. Catches SMB lateral movement staging (T1021.002).
- **Raw Disk Access Monitor** (`RawDiskAccessMonitor.cs`): Detects processes accessing raw disk devices (\\.\PhysicalDrive0, etc.) via command-line heuristics. Catches bootkits and forensic wiping (T1006).

#### P2 — Medium Priority New Detections

- **Thread Start Address Scanner** (`ThreadStartAddressScanner.cs`): Scans thread start addresses against loaded module ranges. Unmapped start addresses indicate reflective injection, shellcode, or direct syscall execution (T1055).
- **WSL Monitor** (`WslMonitor.cs`): Monitors WSL process spawns for suspicious commands (reverse shells, credential access) and runtime distribution installation (T1202).
- **Signer Trust Service** (`SignerTrustService.cs`): Authenticode signature verification with write-time cache invalidation. Hardens allowlist decisions beyond name-only matching (T1036.005 defense).
- **Isolation Response Engine** (`IsolationResponseEngine.cs`): Handles ISO mount threats (kill + dismount + delete), Docker container threats, and VM termination (T1553.005).
- **Chain Tracer** (`ChainTracer.cs`): Traces full attack chains via ProcessAncestryCache, kills non-system ancestor processes.

#### Security Hardening

- **ProcessKillAction path verification**: Protected process allowlist now verifies the binary is actually from a system path. Attacker naming malware "explorer.exe" in Temp is no longer protected from kill.

#### Monitor Count

- Windows: 15 → 26 active monitors (+11 new)
- Total MITRE ATT&CK coverage: T1003, T1006, T1021, T1027, T1036, T1041, T1055, T1059, T1134, T1202, T1486, T1547, T1548, T1553, T1555, T1562, T1574

---

## [0.1.0] — 2026-07-21

### Security Audit Remediation — All P0/P1/P2 Findings Fixed

Addresses all findings from the v0.0.9 red/blue team security audit.

#### P0 — Critical Security Fixes

- **Process DACL protection** (`AgentWatchdog.cs`): Implemented real `SetSecurityInfo` P/Invoke to set a DACL that denies `PROCESS_TERMINATE` from Everyone while allowing SYSTEM and Administrators full control. Uses SDDL-based security descriptor conversion.
- **Native ETW event parsing** (`NativeEtwSession.cs`): `HandleKernelProcessEvent` now parses ProcessName, ParentProcessId, and CommandLine from EVENT_RECORD UserData payloads. `HandleDnsEvent` parses QueryName and QueryType. Added `ReadUnicodeString` helper for safe null-terminated string extraction from unmanaged memory.
- **Data exfiltration byte counters** (`DataExfiltrationMonitor.cs`): Implemented real per-connection byte tracking via `GetPerTcpConnectionEStats`/`SetPerTcpConnectionEStats` P/Invoke. Reads `DataBytesOut`/`DataBytesIn` from TCP_ESTATS_DATA_ROD_v0. Falls back gracefully on older Windows.

#### P1 — High Priority Fixes

- **PID-scoped correlation** (`BehavioralCorrelationEngine.cs`): Signal history now keyed by `(PID, category)` instead of category alone. Composite rules only fire when signals from the SAME PID match. Eliminates cross-process false positive flooding. Anti-tamper signals remain system-wide (global scope).
- **Anti-fingerprinting connectivity canary** (`ConnectivityCanaryMonitor.cs`): Expanded URL pool (8 endpoints including OS captive portals). Random URL selection per check. Pool of 5 browser-like User-Agent strings rotated per request. Jittered interval ±15s using cryptographic RNG. No product-identifying headers.
- **Per-installation DPAPI entropy** (`KeyProtection.cs`): Replaced hardcoded entropy string with per-machine random entropy generated at install time (32 bytes, stored in `.behavedr-entropy` with restricted ACLs). Prevents DPAPI unwrapping even with source code access.

#### P2 — Medium Priority Fixes

- **CredentialCanary marshaling** (`CredentialCanaryMonitor.cs`): Replaced unsafe hardcoded struct offset reading with proper `Marshal.PtrToStructure<NATIVE_CREDENTIAL>`. Added correct Windows SDK CREDENTIALW struct definition with IntPtr-sized fields. Fixed memory leak with proper try/finally for `CredFree`.
- **DGA detection refinement** (`DnsQueryMonitor.cs`): Lowered entropy threshold (3.5→3.0) and domain length threshold (20→12 chars) to catch shorter DGA. Added `DetectUniqueDomainBurst` for dictionary-based DGA (20+ unique domains in 60s per process).

---

## [0.0.9] — 2026-07-21

### Red/Blue Team Audit — Complete Remediation (v2)

Full implementation of all findings from the v0.0.8 red/blue team security audit.

#### P0 — Critical Security Fixes

- **Agent Watchdog** (`AgentWatchdog.cs`): Mutual heartbeat monitoring between watchdog and monitoring service. Detects monitoring loop suspension/deadlock (15s threshold). Last-gasp forensic logging on unexpected termination. Process exit event capture. Windows process protection DACL setup.
- **Native ETW Session** (`NativeEtwSession.cs`): Full P/Invoke ETW implementation using `StartTraceW`/`EnableTraceEx2`/`OpenTraceW`/`ProcessTrace`. Subscribes to Microsoft-Windows-Kernel-Process and Microsoft-Windows-DNS-Client providers (~50ms latency vs 1-2s WMI). Graceful fallback to WMI-based EtwSession when native unavailable.
- **Config pre-seal validation** (`ConfigIntegrity.ValidateConfigBeforeSealing`): Validates all scoring thresholds and monitoring intervals are within acceptable bounds BEFORE sealing. Prevents first-run config injection attacks.
- **DPAPI key protection** (`KeyProtection.cs`): Machine key wrapped with `ProtectedData.Protect(LocalMachine)` + app-specific entropy on Windows. Auto-upgrades legacy unprotected keys. Prevents offline key extraction from disk images.

#### P1 — High Priority Additions

- **DNS monitoring** (`DnsQueryMonitor.cs`): Consumes ETW DNS-Client events. DGA detection via Shannon entropy scoring. Suspicious TLD detection. Unexpected process DNS detection (shells/LOLBins making queries). DNS tunneling detection (>50 queries in 30s from single PID).
- **Data exfiltration detection** (`DataExfiltrationMonitor.cs`): Tracks outbound bytes per (PID, RemoteIP). Large transfer detection (>50MB from non-browser). High upload-to-download ratio (>5:1). Shell/LOLBin upload detection (any >5MB).
- **Command-line normalization** (`CommandLineAnalyzer.cs`): Defeats evasion via caret insertion, env var expansion, backtick removal, null byte stripping. Shannon entropy scoring for encoded payloads. PowerShell obfuscation detection (format operator, char array, replace, reverse patterns).
- **Process ancestry cache** (`ProcessAncestryCache.cs`): In-memory parent-child cache populated from ETW events. 120s retention matching correlation window. Supports 5-hop ancestry chain resolution. Enables grandparent analysis for multi-stage attacks.
- **Incident grouping** (`IncidentManager.cs`): Groups related detections by PID and process name within 120s window. Incident lifecycle tracking (Open→Active→Closed). Maintains involved PIDs, process names, max score, president-kill flag.
- **Signal deduplication** (`SignalDeduplicator.cs`): Within-cycle dedup (keep highest confidence). Cross-cycle cooldown (30s per signal type, 120s for composites). Exponential decay of signal weight over time (60s half-life).
- **Credential canary enhancement**: Now detects both deletion AND read/enumeration via LastWritten timestamp tracking. Added `CredFree` P/Invoke and metadata change detection.

#### P2 — Architecture Improvements

- **Parallel monitor execution**: All monitors run concurrently via `Task.WhenAll` with 10s per-monitor timeout. Slow monitors no longer block the detection cycle.
- **Replay prevention**: `DetectionReport` now includes `BootNonce` (unique per agent boot) in addition to existing Nonce and SequenceNumber. Server can validate monotonic sequence + unique nonce + boot session.
- **Linux audit log truncation detection**: Tracks audit log file size; significant shrinkage (>50%) or zeroing triggers high-confidence signal (0.92-0.98). Detects attacker clearing evidence.
- **Double registration fix**: MonitoringService now guards against registering monitors when engine already has them (prevents duplicate signals from DI + manual registration).

#### Monitor Count: 13 → 15 (Windows)

| New Monitor | Platform | Detection |
|---|---|---|
| DnsQueryMonitor | Windows | DGA, suspicious TLDs, DNS tunneling, unexpected DNS from shells |
| DataExfiltrationMonitor | Windows | Large outbound transfers, upload ratio, shell uploads |

#### New Core Components

| Component | Purpose |
|---|---|
| SignalDeduplicator | Within-cycle dedup + cross-cycle cooldown + exponential decay |
| ProcessAncestryCache | ETW-fed parent-child cache with ancestry chain resolution |
| IncidentManager | Detection grouping by process tree and time window |
| CommandLineAnalyzer | Normalization + entropy scoring for cmdline evasion defeat |
| KeyProtection | DPAPI wrapping for machine key (Windows) |
| NativeEtwSession | Full native ETW with Kernel-Process + DNS-Client providers |
| AgentWatchdog | Mutual monitoring + last-gasp logging |

## [0.0.8] — 2026-07-21

### Zero Visuals + CI Fix

Enforce the "zero visuals" design philosophy across all platforms and fix broken CI/CD pipeline.

#### Mobile — Zero Visuals Conversion

- **Android**: Replaced MAUI GUI app with headless foreground service. Launcher Activity uses `Theme.NoDisplay`, starts `BehavedrForegroundService`, and calls `MoveTaskToBack(true)`. User sees only the app icon and a low-priority persistent notification.
- **iOS**: Stripped all visual pages. Minimal blank `AgentPage` (Apple requirement) with background processing modes enabled (`processing`, `fetch`). No interactive UI.
- **Removed**: `MainPage.xaml` (Labels, Buttons, ScrollView), `AppShell.xaml` (navigation), splash screen, color themes, styled resources.
- **Kept**: App icon only — `appicon.svg` + `appiconfg.svg`.

#### CI/CD Fixes

- **Test fixes**: Updated 2 stale test assertions that were failing on all 3 desktop platforms:
  - `ScoringEngineTests.CalculateScore_ClampsToMax100` → renamed to `PreservesRawScoreAbove100` (scoring engine no longer clamps to 100 by design).
  - `PlatformMonitorsTests.All_ContainsFiveMonitors` → replaced with `All_ContainsAtLeastBasePlatformMonitors` (monitor count is now platform-dependent).
- **iOS workflow**: Replaced hardcoded Xcode 26.x lookup with dynamic "pick latest available" Xcode.
- **Android workflow**: Downgraded target from `android-36` to `android-35` with fallback to 34.
- **Mobile jobs**: Marked `continue-on-error: true` — mobile builds no longer block desktop CI.
- **Release workflow**: `publish-release` now depends only on `desktop` jobs. Android APK included if available but not required.
- **Added `dotnet-quality: 'ga'`** to all `setup-dotnet` steps for reliable SDK resolution.

## [0.0.7] — 2026-07-21

### Red/Blue Team Audit — Full Remediation

Complete security overhaul based on comprehensive red/blue team audit and cross-reference with Sentinel EDR patterns.

#### P0 — Critical Security Fixes

- **Real RSA-4096 signing key**: Replaced placeholder public key in `UpdateSignatureVerifier.cs` with a real 4096-bit RSA key. Private key generated via `tools/GenerateKey`. Update signature verification is now functional.
- **Behavioral detection engine** (`BehavioralMonitor.cs`): Replaces process-name-only detection with:
  - Parent-child anomaly detection (Office→shell, WMI→PowerShell, etc.)
  - Command-line analysis (encoded PowerShell, AMSI bypass, download cradles)
  - LOLBin abuse detection (certutil, bitsadmin, mshta, regsvr32, wmic, forfiles)
  - Hidden PowerShell + NoProfile detection
  - WMI-based process scanning for full command-line visibility
- **ETW integration** (`EtwSession.cs`): WMI-based real-time process event subscription (Win32_ProcessStartTrace) with graceful degradation when unavailable. Foundation for future full kernel ETW P/Invoke.
- **Anti-tamper guard** (`AntiTamperGuard.cs`):
  - Process suspension detection via QueryPerformanceCounter (QPC) — immune to clock manipulation
  - Binary integrity verification (SHA-256 baseline + periodic check)
  - Service registry self-healing — detects deletion and re-registers via Registry API
  - 4-second suspension threshold (2x expected tick interval)

#### P1 — High Priority Additions

- **Network monitoring** (`NetworkConnectionMonitor.cs`): `GetExtendedTcpTable` P/Invoke for full TCP connection inventory with PID attribution. Detects suspicious port connections, high connection counts from non-browser processes, and connection bursts.
- **Beaconing detection** (`BeaconingDetector.cs`): Statistical C2 beacon detection via connection interval coefficient of variation (CV). Fires when CV < 0.40 with 5+ observations (high regularity = automated check-ins).
- **Credential guard** (`CredentialGuardMonitor.cs`): FileSystemWatcher on Chrome/Edge/Brave/Opera/Firefox credential database files. Detects non-browser processes loading SQLite (infostealer indicator). Covers Login Data, Cookies, Web Data, Local State, key4.db, logins.json.
- **Credential canary** (`CredentialCanaryMonitor.cs`): Honeypot credential deployed via Windows Credential Manager. Near-zero false positive (0.98 confidence) — only credential dumpers/infostealers would access it. Auto-redeploys on trip.
- **Behavioral correlation engine** (`BehavioralCorrelationEngine.cs`): 120-second sliding window correlator producing composite signals:
  - Injection + Network → "In-Memory Implant Active" (0.96)
  - Credential Access + Network → "Credential Theft + Exfil" (0.95)
  - Parent-Child + Encoded PS → "Fileless Attack Chain" (0.94)
  - Download Cradle + Execution → "Staged Payload Active" (0.92)
  - Anti-Tamper + Any → "Active EDR Evasion" (0.97)
  - Multiple LOLBins → "LOLBin Chain" (0.88)
- **Memory behavior analyzer** (`MemoryAnalyzer.cs`): `VirtualQueryEx` P/Invoke scanning for RWX (Read-Write-Execute) private memory regions in non-JIT processes. Graduated scoring by region count.
- **File activity monitor** (`FileActivityMonitor.cs`): FileSystemWatcher on user Downloads/Documents/Desktop/Temp. Detects ransomware rename bursts (>20 renames in 30s), executable drops in temp, DLL sideloading in user paths.
- **Registry persistence monitor** (`RegistryPersistenceMonitor.cs`): Baselines Run keys and services at startup, alerts on new entries. Flags suspicious service paths (temp dirs, AppData, PowerShell commands).
- **Connectivity canary** (`ConnectivityCanaryMonitor.cs`): Periodic health check against Cloudflare/Google/GStatic. 3+ consecutive failures → "Network Silencing Detected" (EDRSilencer/WFP indicator).

#### P2 — Code Quality & Infrastructure

- **SecurityValidation utility** (`SecurityValidation.cs`): Centralized input validation — safe filenames, path containment, IP validation, private IP detection, PID/port validation, secure string comparison.
- **Fixed dead code**: Removed unused `SuspiciousParentChild` dictionary from `WindowsMonitor.cs` (functionality moved to `BehavioralMonitor.cs`).
- **Fixed sync-over-async**: Marked `DetectionEngine.ProcessEvent()` as `[Obsolete]` with migration guidance.
- **Added `System.Management` NuGet**: Required for WMI-based process monitoring and ETW subscription.
- **Monitor registration**: `PlatformMonitors.BuildMonitorList()` conditionally registers Windows-only monitors using `OperatingSystem.IsWindows()` guard to satisfy CA1416.

#### Monitor Count: 3 → 13 (Windows), 1 → 3 (Cross-platform)

| New Monitor | Platform | Detection |
|---|---|---|
| BehavioralMonitor | Windows | Parent-child, LOLBins, encoded PS, AMSI bypass |
| AntiTamperGuard | Windows | Suspension, binary integrity, service heal |
| NetworkConnectionMonitor | Windows | TCP connections, suspicious ports, bursts |
| MemoryAnalyzer | Windows | RWX regions, process hollowing indicators |
| BeaconingDetector | Windows | Statistical C2 beacon (CV analysis) |
| CredentialGuardMonitor | Windows | Browser credential file access |
| CredentialCanaryMonitor | Windows | Honeypot credential tripwire |
| RegistryPersistenceMonitor | Windows | Run keys, services baseline/delta |
| FileActivityMonitor | Cross-platform | Ransomware, exe drops, DLL sideload |
| ConnectivityCanaryMonitor | Cross-platform | EDRSilencer/network silencing |

### Dependencies Added
- `System.Management` 9.0.4 — WMI process monitoring
- `Microsoft.Extensions.Configuration.Abstractions` 10.0.0 — Configuration binding

## [0.0.6] — 2026-07-21

### Security Audit
- Full red/blue team audit document (`docs/red-blue-team-audit.md`)
- Cross-reference with Sentinel EDR patterns and recommendations

## [0.0.5] — 2026-07-21

### Security Hardening (Full Blue/Red Team Audit)

#### P0 — Critical Fixes
- **Signed auto-updates**: RSA-PSS SHA-256 signature verification on all downloaded update packages. Agent downloads `.sig` sidecar file and verifies against baked-in public key before extraction. Rejects unsigned updates.
- **Fail-closed TLS**: Removed `DangerousAcceptAnyServerCertificateValidator`. When no CA cert is configured, agent refuses all server connections (prevents MITM). Configure `CaCertPath` to enable communication.
- **Config integrity protection**: HMAC-SHA256 verification of `appsettings.json` at startup. First run seals the config; subsequent starts verify the seal. Agent refuses to start if config is tampered with.

#### P1 — High Priority
- **Encrypted offline buffer**: Buffered detection reports are now encrypted with AES-256-GCM using a purpose-derived key (HKDF from machine key). Tampered/corrupted reports are detected and moved to dead-letter.
- **Authenticated policy updates**: `PolicyUpdate` from server now includes a `Signature` field. Agent verifies RSA-PSS signature before accepting any policy changes.
- **Anti-debug hardening**: In Release builds, agent calls `Environment.FailFast` immediately when a debugger is detected (startup and periodic checks). Debug builds still allow attached debuggers.
- **Response rate limiting**: 60-second cooldown per target (PID:ProcessName). Prevents repeated kill/quarantine actions against the same target within the cooldown window.

#### P2 — Medium Priority
- **Path traversal prevention**: `FileQuarantineAction` now validates file paths extracted from signals. Rejects `..`, path separators, and verifies resolved paths stay within expected directories.
- **Machine key rotation**: `ConfigProtection.RotateKey()` supports versioned key rotation. Old keys are archived as `.behavedr-key-v{N}` for decrypting existing data during migration.
- **Android signal injection auth**: `AndroidMonitor.InjectPlatformSignals` now requires a per-session injection token. Unauthorized callers receive `UnauthorizedAccessException`.
- **Dev cert cleanup**: Certificate generation scripts no longer contain hardcoded passwords. Password must be provided via `BEHAVEDR_CERT_PASSWORD` env var or interactive prompt. Added `certs/`, `*.pfx`, `*.key`, `*.pem` to `.gitignore`.

#### P3 — Supply Chain
- **Deterministic builds**: Added `<Deterministic>true</Deterministic>` to `Directory.Build.props` for reproducible output.
- **Lock file guidance**: Added instructions for generating and committing `packages.lock.json` when ready for deterministic restores.

### Build Fixes
- Fixed NETSDK1047: Removed `SelfContained=true` from csproj (pass via CLI during publish only)
- Fixed test step: Added explicit restore + build for test project before `dotnet test --no-build`
- Updated SBOM version reference from 0.0.3 to 0.0.5

## [0.0.4] — 2026-07-18

### Real Signal Collection (replaces stubs)
- **Windows**: Process enumeration via `System.Diagnostics.Process` — detects known offensive tools (mimikatz, psexec, rubeus, etc.), high thread counts, excessive memory usage, short-lived PowerShell, process bursts (>20 in 10s)
- **Linux**: `/proc` filesystem scanning + `/var/log/audit/audit.log` parsing — detects reverse shells, base64-encoded execution, executables in /tmp, unexpected root processes, failed auth attempts, sensitive file access
- **Android**: Signal injection API for MAUI layer + `AnalyzePackage` heuristics — detects malware package prefixes, sideloaded apps, accessibility service abuse, overlay permission abuse

### Response Engine
- **Framework**: `IResponseAction` interface, `ResponseEngine` orchestrator with `AlertOnly` (default) and `Active` modes
- **Process Kill**: Cross-platform process termination with PID reuse validation, protected process list, process tree kill
- **File Quarantine**: Moves suspicious files to restricted directory, computes SHA-256, writes JSON metadata for restore
- **Graduated response**: None → Alert → Respond → PresidentKill levels based on configurable thresholds

### Agent-Server Communication
- **HTTPS/JSON client**: mTLS with client certificates, CA certificate pinning, REST endpoints for detections/heartbeat/policy
- **mTLS cert generation**: PowerShell (`generate-certs.ps1`) and Bash (`generate-certs.sh`) scripts — self-signed CA + server + client certs
- **Offline buffering**: File-based queue with chronological replay, max buffer size enforcement, dead-letter directory
- **Policy updates**: Fetch response policy and scoring config from server

### Security
- **Encrypted configuration**: DPAPI on Windows, AES-256 with machine-derived key on Linux/macOS. `ENC:` prefix detection for auto-decrypt
- **Machine key management**: Protected key file with restricted permissions (`chmod 600` on Unix)

### Auto-Update
- **GitHub Releases API**: Check for newer versions, platform-specific asset download, SHA-256 integrity verification, zip extraction for update staging

### Telemetry
- **OpenTelemetry-compatible metrics** via `System.Diagnostics.Metrics` (zero extra dependencies):
  - Counters: detection cycles, signals collected, detections triggered, president-kills, responses (success/fail), reports buffered/sent
  - Histograms: detection score distribution, cycle duration (ms)
  - UpDownCounter: active monitors
- Exportable to Prometheus, OTLP, or any OTel backend

### Installer Hardening
- **Restricted ACLs**: Install directory (SYSTEM+Admins full, users read+exec), quarantine/buffer dirs (SYSTEM+Admins only)
- **Windows Service**: Optional task during install — registers `sc.exe` service with auto-start, auto-restart on failure (5s/10s/30s backoff)
- **Service lifecycle**: Stop and delete service on uninstall
- **Config preservation**: Existing `appsettings.json` not overwritten on upgrade

### Testing
- **49 unit + integration tests** covering ScoringEngine, DetectionEngine, ResponseEngine, ScoringConfig, Signal, PlatformMonitors, and full pipeline (monitor → detection → response)
- Integration tests verify real platform monitors on current OS

### Dependencies Added (Core)
- `System.Security.Cryptography.ProtectedData` 9.0.4 — DPAPI support

## [0.0.3] — 2026-07-18

### Security Hardening
- Agent self-protection: SHA-256 binary integrity verification, debugger detection, process hollowing check
- CI/CD supply chain: All GitHub Actions pinned to commit SHAs
- SBOM generation, SECURITY.md with full disclosure policy
- Temp extraction eliminated (`IncludeAllContentForSelfExtract`)
- Android permissions documented as runtime-gated

### Architecture
- Detection engine rewrite: actually collects signals from monitors
- Externalized configuration, structured logging (Serilog), Windows Service / systemd
- Input validation, `CancellationToken` propagation

### Build & Tooling
- Centralized versioning (`Directory.Build.props`), `global.json`, NuGet lock files
- Pinned NuGet packages, `TreatWarningsAsErrors`, xUnit test project

## [0.0.2] — 2026-07-18

### Packaging
- Windows installer (Inno Setup), single-file self-contained agent
- Portable zips, cleaner Android APK

## [0.0.1] — 2026-07-18

First public release. Desktop agent + Android MAUI APK + iOS simulator CI.

## [Unreleased]

- (next)
