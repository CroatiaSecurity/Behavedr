# Platform epics status (0.3.2)

Honest field-readiness of the large epics. Version stays on **0.3.x** patches.

| Epic | Code | Built artifact in CI | Field requirements | Residual |
|------|------|----------------------|--------------------|----------|
| Windows WFP isolation | `WindowsWfpEngine` dual-layer ALE | N/A (user-mode) | SYSTEM elevation | No callout driver |
| Linux eBPF suite | `behavedr_suite.bpf.c`, `LinuxEbpfLoader` | Soft-build `.o` when clang/BTF present | CAP_BPF, install `.o` to `/opt/behavedr/` | Full CO-RE needs BTF host |
| macOS EndpointSecurity | bridge + managed monitor | Soft-build dylib on macOS runners | ES entitlement + dylib | Attach fails without entitlement |
| macOS System Extension | `native/macos/SystemExtension/` | Soft-build on macOS | Apple capability + user approve | Full product packaging TBD |
| Android Play Integrity | package ref + attestor | When MAUI Android restores | Cloud project number | Server decrypt recommended |
| iOS companion | Keychain helper, NE notes, response | MAUI iOS | MDM / App Attest / NE targets | Not full-device EDR |
| OS code signing | release.yml hooks | When secrets set | Paid certs | Optional for agent RSA trust |
| Live policy | `PolicyApplicator` | N/A | Signed policies from server | Server must use policy key |

## What “done” means here

- **Done in code:** loaders, programs, bridges, packaging scripts, soft-fail paths.  
- **Done in field:** only after artifacts + privileges + (where needed) Apple/Google enrollment exist on the host.

cn_proc / kqueue / advfirewall remain automatic fallbacks so agents never go blind.
