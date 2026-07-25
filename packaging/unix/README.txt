Behavedr Agent — Unix packaging
================================

Self-contained single-file binary (no .NET runtime install required).

Quick start
-----------
  chmod +x Behavedr
  sudo ./Behavedr

Linux (systemd) — production
----------------------------
  sudo useradd -r -s /usr/sbin/nologin behavedr 2>/dev/null || true
  sudo mkdir -p /opt/behavedr/{logs,quarantine,buffer,run} /var/lib/behavedr
  sudo cp Behavedr /opt/behavedr/
  sudo cp behavedr.service /etc/systemd/system/
  sudo chown -R behavedr:behavedr /opt/behavedr /var/lib/behavedr
  sudo systemctl daemon-reload
  sudo systemctl enable --now behavedr

  Optional: set IPAddressAllow in the unit to lock egress to your management server.

macOS (launchd) — production
----------------------------
  sudo mkdir -p /opt/behavedr/logs
  sudo cp Behavedr /opt/behavedr/
  sudo cp com.croatiasecurity.behavedr.plist /Library/LaunchDaemons/
  sudo chown root:wheel /Library/LaunchDaemons/com.croatiasecurity.behavedr.plist
  sudo launchctl bootstrap system /Library/LaunchDaemons/com.croatiasecurity.behavedr.plist

  Grant Full Disk Access to /opt/behavedr/Behavedr in System Settings → Privacy.
  Prefer a Developer ID signed + notarized build for Gatekeeper.

v0.2.6 platform coverage
------------------------
  Linux: cn_proc, fanotify, kernel module load detection, auth log bursts,
         nftables isolation, hardened systemd unit (CAP docs + optional IPAllow).
  macOS: kqueue process events (200ms discovery), VNODE file watches on
         LaunchDaemons/Agents/tmp, codesign self + persistence scan,
         route/pf network isolation. Optional: pf-behavedr-block.conf anchor.
  Windows (desktop packaging): see packaging/windows; verify-install-acls.ps1.

GitHub: https://github.com/CroatiaSecurity/Behavedr
