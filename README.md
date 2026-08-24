# RemotePairing Guard

A native macOS menu-bar monitor with application groups and independently configured, code-identity-verified process rules. Apple's `remotepairingd` XPC service is the initial rule.

## Safety model

- Identifies the target by its complete executable path.
- Validates the target has Apple's code signature and the expected code identifier before monitoring.
- Measures `ri_phys_footprint`, not virtual address-space size.
- Only posts passive, silent notifications. It never terminates the target process.
- Repeats an unresolved warning at most once every 30 minutes.

## Defaults

- Monitoring: enabled
- Interval: 1 minute
- Initial `remotepairingd` warning threshold: 1 GB; every rule has its own threshold

Use the menu-bar icon to open the monitoring console. The console organizes rules by application group and edits each threshold directly. An alert notification also offers a text-input action accepting values such as `1.5 GB` or `768 MB`. Move the app to `/Applications` before enabling “Launch at Login.”

## Optional AI analysis

AI analysis is off by default. The menu can store an OpenAI API key in macOS Keychain and enable a second opinion only when the deterministic local threshold is first crossed. The request uses the Responses API with Structured Outputs and `store: false`; it includes only the verified target identity, configuration, and up to ten memory samples. Local alerts remain functional if AI is disabled or unavailable.

## Build

```sh
chmod +x scripts/build.sh
scripts/build.sh
```
