# Process Memory Guard 2.1.1

Process Memory Guard is a native macOS menu-bar monitor for signed process rules. Rules remain organized by application group and every rule keeps its own physical-memory threshold. A group may additionally have an optional aggregate threshold for the sum of its enabled members.

## Event semantics

- The measured value is `ri_phys_footprint`, summed across matching PIDs.
- A normal rule or group threshold needs two consecutive samples at or above the threshold before a `warning` incident starts. Reaching at least twice the threshold makes the incident `critical` immediately.
- An active incident recovers only after two consecutive samples below 85% of its threshold. A sample between 85% and the threshold does not recover it.
- Every incident records its start time, peak, severity, notification count, and one-hour snooze deadline. The first alert is local and immediate; a warning-to-critical upgrade may alert once; reminders are at least 30 minutes apart and an incident receives no more than three notifications.
- `DispatchSourceMemoryPressure` maintains `unknown`, `normal`, `warning`, and `critical`. Host pressure can raise the displayed status/icon, but never starts an incident by itself.

The console distinguishes `未运行`, `已禁用`, `身份失效`, `正常`, `warning`, and `critical`, and shows current value, incident/session peak, a compact trend, and group member contributions. Notification actions open and focus the rule, accept a new rule threshold directly, or pause the event for one hour.

The console also automatically discovers readable live processes through macOS `libproc`, grouped by exact executable path like a lightweight Activity Monitor. Discovery is observational and refreshed on the normal interval; it does not silently create alert rules. Use “监视” on a discovered row to promote it into a persistent, code-identity-verified rule with a conservative initial threshold.

## Safety model

- Identifies each target by its complete executable path.
- Validates the target's Apple/designated code-signing requirement before monitoring it.
- Never terminates or changes a monitored process.
- Notifications are passive and locally generated. Permission denial does not stop the menu-bar console.

## Defaults

- Monitoring: enabled
- Interval: 1 minute (minimum 15 seconds)
- Initial `remotepairingd` rule threshold: 1 GB
- AI: disabled

Move the built app to `/Applications` before enabling “Launch at Login.”

## Optional AI second opinion

AI is an optional, independent annotation. The local threshold event is sent immediately and does not wait for a model. When AI is enabled and a live incident has at least five samples, one request is started in parallel (up to ten oldest-to-newest samples). A failed request is shown as an annotation error and never changes the incident or local notifications. The payload contains only the application-group name, concrete rule identity/signing identifier, rule/group thresholds, interval, and physical-footprint samples; it does not contain a process list, files, logs, or device identifier. The Responses request uses `store: false`.

The AI panel provides “测试连接” and “删除密钥”, and discloses the payload and approximate call scale. The key is stored only in the macOS Keychain. With AI disabled, automatic monitoring performs no network request; connection testing is an explicit user action.

## Build and install

```sh
chmod +x scripts/build.sh
scripts/build.sh
```

The script compiles every Swift file under `Sources`, creates `outputs/Process Memory Guard.app`, embeds `LICENSE` in the app Resources and source archive, runs the app self-check, and writes `outputs/SHA256SUMS` for the two zip artifacts. The self-check prints version, signing identity, this process's physical footprint, and the target scan result. Copy the app bundle to `/Applications` to install it.

GitHub Actions performs only this macOS build/self-check and checksum existence check; the project intentionally adds no test suite.
