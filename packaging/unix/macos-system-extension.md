# macOS Endpoint Security System Extension (scaffold)

For enterprise deployment beyond an entitled daemon, host the ES client in a
**System Extension** and XPC events to Behavedr.

## Layout (recommended)

```
Behavedr.app/
  Contents/MacOS/Behavedr          # agent
  Contents/Library/SystemExtensions/
    com.croatiasecurity.behavedr.es.systemextension
```

## Entitlements

- `com.apple.developer.endpoint-security.client`
- `com.apple.developer.system-extension.install`

## Bridge reuse

The C ABI in `native/macos/es_bridge/behavedr_es_bridge.c` (`behavedr_es_*`) is
intentionally small so the same code can live in the extension process.

## AUTH mode

Set `BEHAVEDR_ES_AUTH=1` on the extension host to subscribe AUTH_EXEC/AUTH_OPEN
with a **conservative denylist** (tmp droppers, known tool names). Default is
NOTIFY-only telemetry.

## Activation

```bash
systemextensionsctl list
# User must approve in System Settings → Privacy → System Extensions
```

This document is packaging guidance; full Xcode project generation is left to
release engineering per Apple’s current System Extension templates.
