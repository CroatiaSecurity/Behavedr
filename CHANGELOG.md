# Changelog

## [0.0.1] — 2026-07-18

First public release.

### Platforms
- **Desktop agent:** Windows (`win-x64`), Linux (`linux-x64`), macOS (`osx-arm64`)
- **Android:** MAUI app (`net10.0-android`, arm64)
- **iOS:** MAUI app builds in CI for simulator only (no device IPA yet)

### Core
- GIDR President + Council of Elders scoring (`DetectionEngine`, `ScoringEngine`)
- Shared monitors: Windows, Linux, macOS, Android, iOS
- `AgentBootstrap` / `PlatformMonitors` registration

### CI / packaging
- Build on push/PR; Release workflow on `v*` tags
- Self-contained desktop zips + Android package attached to GitHub Releases

### Known limitations
- Behavioral hooks are stubs (not production EDR sensors yet)
- iOS real-device / TestFlight requires Apple Developer signing
- No installers, auto-update, or code-signed desktop packages

## [Unreleased]

- (next)
