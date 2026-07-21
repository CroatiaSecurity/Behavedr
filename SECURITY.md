# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.0.5   | Yes       |
| < 0.0.5 | No        |

Only the latest release receives security patches. Upgrade promptly when a new version is published.

## Reporting a Vulnerability

We take security issues in Behavedr seriously. If you discover a vulnerability, please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub issue** for security vulnerabilities.
2. Email your report to: **security@croatiasecurity.com**
3. Alternatively, use [GitHub Security Advisories](https://github.com/CroatiaSecurity/Behavedr/security/advisories/new) to report privately.

### What to Include

- Description of the vulnerability
- Steps to reproduce (proof of concept if possible)
- Affected version(s)
- Potential impact assessment
- Suggested fix (if you have one)

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Within 30 days for critical, 90 days for others |
| Public disclosure | Coordinated with reporter after fix is released |

### What to Expect

- You will receive an acknowledgment with a tracking reference.
- We will keep you informed of progress toward a fix.
- We will credit you in the release notes (unless you prefer anonymity).
- We will not take legal action against researchers who follow responsible disclosure.

## Scope

The following are in scope for security reports:

- Agent binary (desktop: Windows, Linux, macOS)
- Mobile app (Android, iOS)
- Detection and scoring engines
- Self-protection mechanisms
- Build pipeline and supply chain
- Configuration handling

### Out of Scope

- Issues in third-party dependencies (report upstream; let us know so we can track)
- Social engineering attacks against CroatiaSecurity personnel
- Denial of service against CI/CD infrastructure

## Security Design Principles

Behavedr follows these security principles:

- **Userland-first**: The agent operates without kernel drivers where possible.
- **Least privilege**: Permissions are requested only when features require them.
- **Defense in depth**: Self-protection, integrity checks, and structured logging.
- **Minimal attack surface**: Single-file deployment, no temp extraction, pinned dependencies.
- **Transparency**: Open source, SBOM generated with each release.

## Known Limitations

- Code signing for the agent binary is not yet implemented (planned for v0.1.0).
- Update signing uses a placeholder public key — replace before production deployment.
- Policy signature verification uses the same placeholder key infrastructure.
- Mobile monitoring capabilities are in early development (stub implementations on iOS/macOS).
- Key rotation requires manual invocation of `ConfigProtection.RotateKey()`.

## Security Features (v0.0.5)

- Signed auto-updates with RSA-PSS SHA-256 verification
- Fail-closed TLS (no connections without CA cert pinning)
- Config file HMAC integrity protection
- Encrypted offline buffer (AES-256-GCM)
- Authenticated policy updates (server must sign)
- Anti-debug protection (FailFast in Release builds)
- Response action rate limiting (60s cooldown per target)
- Path traversal prevention in file quarantine
- Machine key versioning and rotation support
- Android signal injection authentication
- Deterministic builds enabled
