# Platform monitors

Registered at runtime via `PlatformMonitors` / `AgentBootstrap` when `IsSupported` is true.

| Monitor | OS | Notes |
|---------|-----|-------|
| WindowsMonitor | Windows | Base process heuristics |
| DriverLoadMonitor | Windows | BYOVD / vulnerable driver (v0.2.2, Sentinel-inspired) |
| LinuxMonitor | Linux | Base process heuristics |
| MacOSMonitor | macOS | Base process heuristics |
| MacOSKqueueMonitor | macOS | Real-time process events |
| AndroidMonitor | Android | Root/process + platform signal injection |
| IosMonitor | iOS / Catalyst | Jailbreak heuristics (preview) |
| + many specialized monitors | per-OS | See `PlatformMonitors.BuildMonitorList` |
