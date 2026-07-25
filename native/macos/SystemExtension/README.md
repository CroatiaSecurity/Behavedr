# Behavedr Endpoint Security System Extension (0.3.2)

## Layout

```
native/macos/SystemExtension/
  Info.plist
  entitlements.plist
  main.m                 # ES client host (XPC-ready stub)
  build.sh
```

## Capabilities required (Apple Developer)

- Endpoint Security client
- System Extension install

## Build

```bash
cd native/macos/SystemExtension
./build.sh
# produces: dist/com.croatiasecurity.behavedr.es.systemextension
```

Install requires a containing app bundle and user approval in System Settings.

The shared bridge in `../es_bridge/behavedr_es_bridge.c` can be linked into either
the agent daemon (entitled) or this system extension.
