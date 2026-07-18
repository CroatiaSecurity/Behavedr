# Changelog

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
