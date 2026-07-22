# Behavedr

Behavioral endpoint detection and response agent. Monitors process activity, network connections, and system integrity in real time. Produces scored detections and executes configurable response actions.

## Platforms

| Platform | Status |
|----------|--------|
| Windows (x64) | Production — Full detection + response |
| Linux (x64) | Production — Full detection + response |
| macOS (ARM64) | Production — Full detection + response |
| Android | Production — Full EDR: detection, response, VPN inspection, hardware-backed crypto, Play Integrity |
| iOS | Production — Jailbreak detection, sandbox monitoring, dylib injection |

## Quick Start

**Windows (installer):**
```
Behavedr-Setup-<version>-win-x64.exe
```

**Windows (portable):**
```
Behavedr.exe
```

**Linux:**
```
chmod +x Behavedr
sudo ./Behavedr
```

## Building from Source

Requires .NET 10 SDK.

```powershell
# Windows — full installer build
.\installer\build.ps1

# Any platform — portable binary only
dotnet publish src/Behavedr.Agent/Behavedr.Agent.csproj -c Release -r win-x64 --self-contained
```

## Documentation

| Document | Contents |
|----------|----------|
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, security design, supported versions |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threat model, attack surface, trust boundaries |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [docs/](docs/) | Architecture decisions, audit reports |

## License

This software is provided under the terms specified in the repository license file. If no license file is present, all rights are reserved by CroatiaSecurity.

## Legal

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR CONTRIBUTORS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

**Behavedr is endpoint security software that monitors system activity and may terminate processes or quarantine files based on behavioral analysis.** Deployment and operation of this software is the sole responsibility of the operator. The operator must ensure compliance with all applicable laws, regulations, and organizational policies governing endpoint monitoring, data collection, and automated response actions in their jurisdiction.

CroatiaSecurity is not responsible for:
- Data loss resulting from automated response actions (process termination, file quarantine)
- System instability caused by interaction with other security software
- False positive detections leading to disruption of legitimate processes
- Regulatory non-compliance arising from deployment without appropriate authorization

By installing or running this software, the operator acknowledges these terms and accepts full responsibility for its configuration and operation.

---

Copyright (c) 2026 CroatiaSecurity. All rights reserved.
