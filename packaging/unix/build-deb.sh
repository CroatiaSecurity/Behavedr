#!/usr/bin/env bash
# Build a simple Debian package for Behavedr (0.2.9+).
# Usage: ./packaging/unix/build-deb.sh <version> <path-to-linux-x64-publish-dir>
set -euo pipefail

VERSION="${1:?version e.g. 0.2.9}"
PUBLISH="${2:?publish dir containing Behavedr binary}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

PKG="behavedr_${VERSION}_amd64"
mkdir -p "$STAGE/$PKG/DEBIAN" \
         "$STAGE/$PKG/opt/behavedr" \
         "$STAGE/$PKG/etc/systemd/system" \
         "$STAGE/$PKG/usr/share/doc/behavedr"

install -m 0755 "$PUBLISH/Behavedr" "$STAGE/$PKG/opt/behavedr/Behavedr"
install -m 0644 "$ROOT/packaging/unix/behavedr.service" "$STAGE/$PKG/etc/systemd/system/behavedr.service"
install -m 0644 "$ROOT/packaging/unix/README.txt" "$STAGE/$PKG/usr/share/doc/behavedr/README"
if [[ -f "$ROOT/packaging/unix/pf-behavedr-block.conf" ]]; then
  install -m 0644 "$ROOT/packaging/unix/pf-behavedr-block.conf" "$STAGE/$PKG/opt/behavedr/"
fi

cat > "$STAGE/$PKG/DEBIAN/control" <<EOF
Package: behavedr
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: CroatiaSecurity <security@croatiasecurity.com>
Depends: systemd
Description: Behavedr behavioral EDR agent (Linux)
 Userland endpoint detection and response agent.
EOF

cat > "$STAGE/$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
getent group behavedr >/dev/null || groupadd --system behavedr
getent passwd behavedr >/dev/null || useradd --system --gid behavedr --home /var/lib/behavedr --shell /usr/sbin/nologin behavedr
mkdir -p /var/lib/behavedr /opt/behavedr/logs /opt/behavedr/quarantine /opt/behavedr/buffer
chown -R behavedr:behavedr /var/lib/behavedr /opt/behavedr
systemctl daemon-reload || true
echo "Behavedr installed. Enable with: systemctl enable --now behavedr"
EOF
chmod 0755 "$STAGE/$PKG/DEBIAN/postinst"

dpkg-deb --build "$STAGE/$PKG" "behavedr_${VERSION}_amd64.deb"
echo "Built behavedr_${VERSION}_amd64.deb"
