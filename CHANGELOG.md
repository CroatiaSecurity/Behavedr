# Changelog

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
