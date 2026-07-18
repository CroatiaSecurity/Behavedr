# Changelog

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
