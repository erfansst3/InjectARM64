# GSpace Libc Hook Test

Minimal ARM64 Android test app for validating GSpace's native hook API from inside a GSpace-hosted guest process.

The app resolves GSpace's exported `MSHookFunction` directly from the already-loaded `libgspace_64.so`, resolves the Android libc `puts` export, and asks GSpace's hook engine to inline-hook that libc function.

The test does not target another application and does not alter procfs or ART state. The hook preserves original behavior. The `READ` button probes `/dev/zero` through the hooked libc `read` and reports callback hits, so a second clone can be tested without pressing HOOK again.

Expected result after pressing **RUN LIBC HOOK**:
- `MSHookFunction=YES`
- `libc_puts=YES`
- `local_libc_hook=YES`
- `CALLBACK hits=1` (or higher if other code calls `puts`)
- `RESULT: PASS`

ARM64 only.
