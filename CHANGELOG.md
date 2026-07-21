# Changelog

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
