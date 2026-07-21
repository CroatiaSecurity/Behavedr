# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.6   | Yes       |
| < 0.1.6 | No        |

Only the latest release receives security patches. Upgrade promptly when a new version is published.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

### How to Report

1. Email: **security@croatiasecurity.com**
2. Or use [GitHub Security Advisories](https://github.com/CroatiaSecurity/Behavedr/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce (proof of concept if possible)
- Affected version(s)
- Potential impact assessment
- Suggested fix (if you have one)

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix (critical) | 30 days |
| Fix (other) | 90 days |
| Disclosure | Coordinated with reporter after fix ships |

We will credit reporters in release notes unless anonymity is preferred. We do not take legal action against researchers who follow responsible disclosure.

## Scope

**In scope:**
- Agent binary (Windows, Linux, macOS)
- Detection and scoring engines
- Self-protection mechanisms
- Cryptographic operations and key management
- Communication layer (mTLS, policy, updates)
- Build pipeline and supply chain
- Installer and packaging scripts
- Configuration handling and integrity verification

**Out of scope:**
- Third-party dependency vulnerabilities (report upstream; notify us for tracking)
- Social engineering against CroatiaSecurity personnel
- Denial of service against CI/CD infrastructure

## Security Architecture

### Design Principles

- **Userland operation.** No kernel driver requirement. Reduces attack surface and deployment complexity at the cost of kernel rootkit visibility. Full behavioral detection on Windows (ETW + P/Invoke), Linux (/proc + audit), and macOS (process enumeration + lsof/vmmap).
- **Least privilege where possible.** SYSTEM context is required for ETW, process inspection, and response actions. File permissions are restricted to SYSTEM and Administrators.
- **Defense in depth.** Multiple independent self-protection mechanisms. No single bypass disables all detection.
- **Fail-closed communication.** TLS connections are rejected without a valid pinned CA certificate. No fallback to insecure transport.
- **Cryptographic integrity.** All local storage uses authenticated encryption (AES-256-GCM). Configuration files are HMAC-sealed. Updates require RSA-4096 PSS signatures.
- **Minimal attack surface.** Single-file deployment. No temp extraction. Deterministic builds. Pinned dependencies with lock files.

### Cryptographic Inventory

| Operation | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Machine key protection | DPAPI (LocalMachine) + entropy | 256-bit | Per-install random entropy prevents cross-machine unwrap |
| Local encryption | AES-256-GCM | 256-bit | Purpose-specific keys derived via HKDF-SHA256 |
| Config integrity | HMAC-SHA256 | 256-bit | Key derived from machine key via HKDF |
| Update signing | RSA-PSS SHA-256 | 4096-bit | Private key offline; public key baked into binary |
| Policy signing | RSA-PSS SHA-256 | 4096-bit | Same key infrastructure as updates |
| Transport | TLS 1.3 (mTLS) | 2048-bit client cert | CA-pinned; fail-closed |
| Config value encryption | AES-256-GCM (cross-platform) / DPAPI (Windows) | 256-bit | DPAPI uses LocalMachine scope |
| macOS key storage | Keychain Services (System Keychain) | 256-bit | Via `security` CLI; backed by Secure Enclave on Apple Silicon |

### Self-Protection Mechanisms (v0.1.6)

| Mechanism | Check Interval | Description |
|-----------|---------------|-------------|
| Process DACL | Startup | Denies PROCESS_TERMINATE to Everyone except SYSTEM/Admins |
| Anti-debug | 30s | FailFast on Debugger.IsAttached in Release builds |
| Binary integrity | 10s | SHA-256 of running executable vs startup baseline |
| QPC suspension detection | ~2s | Detects NtSuspendProcess via performance counter gap |
| Service registry self-healing | 10s | Re-registers service if registry key deleted |
| ETW session liveness | 10s | QueryTraceW verifies session not killed externally |
| ntdll!EtwEventWrite integrity | 10s | Prologue byte comparison against startup baseline |
| amsi!AmsiScanBuffer integrity | 10s | Prologue byte comparison against startup baseline |
| Safe Mode persistence | Install-time | Registry entries for Minimal and Network Safe Boot |
| SCM failure recovery | Service-level | Restart at 5s, 10s, 30s after unexpected stop |
| Config HMAC seal | Startup | Refuses to start if config has been tampered |
| Connectivity canary | ~45s (jittered) | Detects network isolation/firewall silencing |
| Watchdog heartbeat | 3s | Detects monitoring loop suspension or deadlock |
| macOS kqueue process monitor | Real-time | Detects process exec/fork/exit via kernel events |
| macOS Keychain key storage | Startup | Machine key in System Keychain (not on filesystem) |
| macOS proc_pidpath kill verify | On response | Verifies process identity before termination |
| Linux ProtectProc=invisible | Service-level | Hides agent from /proc enumeration |
| Linux syscall filtering | Service-level | Blocks mount/reboot/swap/obsolete syscalls |
| Linux nftables rate limiting | On response | Max 100 isolation rules (prevents DoS) |
| Memory secret zeroing | On use | CryptographicOperations.ZeroMemory after key derivation |

### Supply Chain Controls

- **Deterministic builds** enabled in Directory.Build.props
- **Package lock files** committed (RestorePackagesWithLockFile)
- **Pinned CI action SHAs** (no floating tags)
- **SBOM generation** on Linux release builds
- **Signed auto-updates** with RSA-4096 PSS verification
- **Local build capability** via installer/build.ps1 (no CI dependency)
- **No runtime package downloads** during build (ISCC discovered locally)

## Known Limitations

- No kernel-level visibility. Kernel rootkits can hide from all monitors.
- Native ETW requires elevation (SYSTEM/admin). Falls back to WMI polling without it.
- macOS monitors use process enumeration and lsof/vmmap rather than EndpointSecurity.framework (planned for future release).
- Linux monitors use /proc filesystem and audit logs rather than eBPF (planned for future release).
- Single-process architecture. A successful SYSTEM-level kill terminates all protection until SCM restart (5s).
- Auto-update rollback is not implemented. A corrupted update that passes signature verification could prevent startup.
- DPAPI entropy fallback to fixed value when filesystem is unwritable (containers). Logged as CRITICAL.
- No WFP (Windows Filtering Platform) integration for real-time network filtering.
- No driver load monitoring.
