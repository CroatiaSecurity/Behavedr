# Behavedr

Multi-platform behavioral EDR: **Windows, Linux, macOS, Android, iOS**.

**Current release:** [v0.0.1](https://github.com/CroatiaSecurity/Behavedr/releases/tag/v0.0.1)

**Core:** GIDR President (closed-list kills), Council of Elders weighted signals, userland-first.

Built with .NET 10. Desktop agent + .NET MAUI phone app share `Behavedr.Core`.

## Platforms

| Platform | Project | Runtime ID / TFM |
|----------|---------|------------------|
| Windows | `Behavedr.Agent` | `win-x64` |
| Linux | `Behavedr.Agent` | `linux-x64` |
| macOS | `Behavedr.Agent` | `osx-arm64` |
| Android | `Behavedr.Mobile` | `net10.0-android` |
| iOS | `Behavedr.Mobile` | `net10.0-ios` |

Monitors live in `Behavedr.Core` (`WindowsMonitor`, `LinuxMonitor`, `MacOSMonitor`, `AndroidMonitor`, `IosMonitor`) and register via `AgentBootstrap` / `PlatformMonitors`.

### Phone notes

- **Android** — UsageStats / package query / accessibility-class hooks (stubs + permission declarations).
- **iOS** — Sandbox-limited; config profile / network-filter class signals (stubs). Full enterprise reach needs MDM / Network Extension entitlements.

## Build

### Desktop agent

```bash
dotnet build src/Behavedr.Agent/Behavedr.Agent.csproj -c Release
dotnet publish src/Behavedr.Agent/Behavedr.Agent.csproj -c Release -r win-x64 --self-contained -o publish/agent
```

### Mobile (requires MAUI workloads)

```bash
dotnet workload install maui-android maui-ios
dotnet build src/Behavedr.Mobile/Behavedr.Mobile.csproj -c Release -f net10.0-android
dotnet build src/Behavedr.Mobile/Behavedr.Mobile.csproj -c Release -f net10.0-ios
```

## CI

GitHub Actions builds desktop (3 OS), Android APK, and iOS (simulator, no codesign).

## Releases

Tag a version to publish binaries:

```bash
git tag v0.0.1
git push origin v0.0.1
```

The **Release** workflow attaches self-contained agent zips + Android package to [GitHub Releases](https://github.com/CroatiaSecurity/Behavedr/releases).

Icon: use assets under `Assets/` / MAUI `Resources/`.
