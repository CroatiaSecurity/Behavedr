# macOS EndpointSecurity packaging

Behavedr v0.2.7+ can consume **EndpointSecurity.framework** when the native bridge
and entitlements are present. Without them, **kqueue** remains the real-time path.

## Components

| Piece | Path |
|-------|------|
| Managed monitor | `MacOSEndpointSecurityMonitor` |
| Native bridge | `native/macos/es_bridge/behavedr_es_bridge.c` → `libbehavedr_es.dylib` |
| Install location | `/opt/behavedr/libbehavedr_es.dylib` (or next to agent) |

## Build bridge

```bash
clang -dynamiclib -o libbehavedr_es.dylib native/macos/es_bridge/behavedr_es_bridge.c \
  -framework EndpointSecurity -framework CoreFoundation
sudo mkdir -p /opt/behavedr
sudo cp libbehavedr_es.dylib /opt/behavedr/
```

## Entitlement

The **agent process** (or a System Extension host) needs:

```xml
<key>com.apple.developer.endpoint-security.client</key>
<true/>
```

This requires an Apple Developer Program capability request. Unsigned/local builds
will see `es_new_client` fail — that is expected; kqueue continues to operate.

## Full Disk Access

Grant FDA to `/opt/behavedr/Behavedr` in System Settings → Privacy & Security.

## Production shape (optional System Extension)

For App Store / enterprise-hardened deployment, host the ES client inside an
Endpoint Security **System Extension** and XPC to the agent. The bridge API
(`behavedr_es_*`) is intentionally small so it can move into an extension later.

## Verification

Agent log on success:

```
[ES] EndpointSecurity client subscribed (EXEC/FORK/EXIT/OPEN)
```

On failure (no entitlement):

```
[ES] es_new_client failed … kqueue path remains active
```
