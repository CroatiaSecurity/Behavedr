# Changelog

## [Unreleased]

- Multi-platform EDR scope: Windows, Linux, macOS, **Android**, **iOS**.
- `AndroidMonitor` + `IosMonitor` with phone-class signal stubs.
- Shared `AgentBootstrap` / `PlatformMonitors` catalog for all OSes.
- `Behavedr.Mobile` .NET MAUI app (`net10.0-android`, `net10.0-ios`).
- CI: desktop matrix + Android publish + iOS simulator build.
- Desktop-only fix: valid `net10.0` TFMs (drop invalid `net10.0-linux`).

## [0.1.0]

- Initial cross-platform port with .NET 10, behavioral core, President/Council logic.
