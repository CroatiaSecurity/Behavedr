# Changelog

## [0.0.3] — 2026-07-18

### Security Hardening
- **Agent self-protection**: SHA-256 binary integrity verification at startup and periodic re-check; debugger detection; process hollowing check
- **CI/CD supply chain**: All GitHub Actions pinned to commit SHAs (no tag-only references)
- **SBOM generation**: Software Bill of Materials produced on each release (Linux runner)
- **SECURITY.md**: Full vulnerability disclosure policy with reporting instructions, response timeline, and scope
- **Temp extraction eliminated**: Switched from `IncludeNativeLibrariesForSelfExtract` to `IncludeAllContentForSelfExtract` (no TOCTOU window)
- **Android permissions**: Documented as runtime-gated; added `POST_NOTIFICATIONS` for Android 13+; removed undeclared accessibility service assumption

### Architecture
- **Detection engine rewrite**: `DetectionEngine.ProcessEventAsync` now actually collects signals from registered platform monitors (was dead code before)
- **Externalized configuration**: Scoring thresholds, monitoring interval, and self-protection flags in `appsettings.json`
- **Structured logging**: Serilog with console + rolling file sinks; lifecycle and detection events logged
- **Windows Service / systemd**: Agent runs as a proper background service via `Microsoft.Extensions.Hosting`
- **Monitoring loop**: `MonitoringService` runs periodic detection cycles with configurable interval
- **Input validation**: `ScoringEngine` clamps weight [0,100] and confidence [0,1]; null checks throughout

### Build & Tooling
- **Centralized versioning**: `Directory.Build.props` is the single source of truth for version, company, and compiler settings
- **global.json**: Pins .NET SDK to 10.0.100 with `latestPatch` roll-forward
- **NuGet lock files**: `RestorePackagesWithLockFile` enabled for deterministic restores
- **Pinned NuGet packages**: All package references use exact versions (no wildcards)
- **TreatWarningsAsErrors**: Enabled solution-wide
- **Test project**: 34 xUnit tests covering ScoringEngine, DetectionEngine, ScoringConfig, Signal, and PlatformMonitors

### Packaging
- Windows installer unchanged (Inno Setup)
- Chocolatey install step now requests `--checksum-type sha256`
- Release workflow runs tests before publishing artifacts

## [0.0.2] — 2026-07-18

### Packaging
- **Windows installer** (`Behavedr-Setup-*-win-x64.exe`) via Inno Setup — Program Files, Start Menu, uninstall
- **Single-file** self-contained agent (`Behavedr.exe` / `Behavedr`) — no dump of dozens of runtime DLLs
- Portable zips for Windows / Linux / macOS with README
- Cleaner Android asset: one `Behavedr-*-android.apk`

### Notes
- Prefer the Setup.exe on Windows; the old v0.0.1 zip was a raw `dotnet publish` folder

## [0.0.1] — 2026-07-18

First public release (raw publish layout — superseded for Windows by 0.0.2 installer).

### Platforms
- Desktop agent: Windows, Linux, macOS
- Android MAUI APK
- iOS simulator CI only

## [Unreleased]

- (next)
