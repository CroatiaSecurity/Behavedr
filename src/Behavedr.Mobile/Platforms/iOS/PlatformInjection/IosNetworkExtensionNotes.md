# iOS Network Extension (MDM companion)

Full traffic inspection on iOS requires a **Network Extension** (content filter or
packet tunnel) and typically supervised/MDM enrollment.

## Product shape

1. App Attest / DeviceCheck — `IosAppAttestMonitor` + platform injection  
2. Keychain machine key — `IosKeychainProtection`  
3. Content filter provider (separate NE target) feeds DNS/URL signals into `IosNetworkMonitor.InjectNetworkSignals`  
4. Response limited to container quarantine + MDM commands (`IosResponseEngine`)

## Entitlements

- `com.apple.developer.networking.networkextension`
- App Groups for XPC between host and extension
- App Attest entitlement when using DCAppAttestService

This is intentionally **not** full-device EDR; document limits to operators.
