# Orbit implementation validation

Validated on 2026-11-16 in the shared Linux development environment. The Orbit
series comprises 100 commits after baseline `7fcf5c6`; each was pushed to `main`.

## Implemented workflow

* Responsive panel navigation, workspace header, sign-in and routing editor.
* Authenticated subscription routing settings, transactional updates and
  versioned JSON exports. Text/base64 formats retain their key-only format.
* Android globe connection control, server picker, ordered authenticated
  fallback, JSON/text/base64 imports and per-profile routing overrides.
* Android Keystore encrypted profile storage, explicit profile removal,
  DNS capture routes, application exclusions and fail-closed IPv6 capture.
* CI builds Linux/panel and Android, runs Android contract tests and verifies
  all eight JNI functions for all three Android ABIs.

## Executed checks

| Check | Observed result |
| --- | --- |
| Rust workspace tests, `cargo test --locked --workspace` | Passed; default ignored tests remain ignored |
| Workspace clippy, all targets, warnings denied | Passed |
| JNI feature clippy, all targets, warnings denied | Passed |
| JNI feature tests | 6 passed |
| Panel backend tests | 62 passed, 0 failed |
| Rust formatting for workspace and separate panel backend | Passed |
| Frontend TypeScript build and Vite production build | Passed |
| Android `testDebugUnitTest` | 14 passed, 0 failed |
| Android `assembleDebug` | Passed with native libraries packaged |
| Native release builds | arm64-v8a, armeabi-v7a, x86_64 passed |
| APK contents | `libbproto.so` present for all three ABIs |
| JNI export inspection | All eight required exports present for every ABI |
| Native loopback demo with `RUST_LOG=error` | Authenticated handshake, assigned address `10.66.0.2`, session completed |
| Shell syntax and Git whitespace checks | Passed |

The demo initially timed out because its readiness check depended on an info
log hidden by the inherited log filter. The demo now explicitly enables server
info events while preserving the caller's other filters. The corrected demo
was rerun successfully.

## Limits of this evidence

The APK has not been exercised on a physical device or emulator in this task.
The loopback demo does not exercise TUN, NAT, system DNS or Internet forwarding.
The debug APK uses a development signing key, not a persistent release key.
No target-network censorship or allowlist test was performed. Ordered fallback
selects the first reachable authenticated endpoint; it neither measures the
fastest server nor reconnects an established tunnel automatically after failure.
Routing cannot make a blocked server reachable. Transport disguise and guaranteed
allowlist bypass are not implemented. Refer to `ROUTING-RU.md` for details.

These are current-machine results. GitHub Actions results must be checked on
the final push; local validation does not assert that a hosted workflow passed.
