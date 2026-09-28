# GSpace Hook Test

Minimal ARM64 Android test app that resolves GSpace's exported `MSHookFunction` directly from the already-loaded `libgspace_64.so` and uses it to hook a local native test function.

The test is deliberately self-contained: it does not modify `/proc/*` or hook libc/ART. A successful run shows the original return value, the hooked return value, callback count, and trampoline call.

ARM64 only.
