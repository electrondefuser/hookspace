# HookSpace

A native Android app for detecting userspace hooking frameworks at runtime. Built primarily to study what a hooked process actually looks like from the inside, and to understand where detection breaks down.

The app runs three independent scan methods and compares their results. The interesting case is not just "is Frida present" but "does libc agree with the kernel about what is present" — divergence between the two scan paths is itself a detection signal.

Tested on Pixel 7, Android 16. Requires a rooted device for anything meaningful.

---

## Background

Most Android hook detection you find online either checks a single thing (maps keyword scan) or wraps a Java library that is trivially bypassable by the time Frida gets to it. The goal here was to build something where bypassing one layer does not automatically bypass all of them, and to understand the architectural limits of userspace detection in general.

The short answer to those limits is in `KERNEL_BYPASS.md`.

---

## Detection Methods

### libc Scanning

Reads `/proc/self/maps`, `/proc/self/status`, `/proc/self/task/[tid]/status`, and `/proc/self/fd/*` using standard libc functions — `fopen`, `readdir`, `read`, `readlink`. Looks for:

- Hook-related strings in mapped regions: `frida`, `gadget`, `xposed`, `substrate`, `magisk`, `lsposed`, `zygisk`, `linjector`
- rwxp pages backed by `.so` files — Frida `mprotect`s pages before writing trampolines, leaving them rwx even when no `Interceptor.attach()` calls have been made
- `TracerPid` nonzero in `/proc/self/status`
- Frida thread names in the task list: `gum-js-loop`, `gmain`, `gdbus`, `pool-frida`
- Suspicious named pipes in `/proc/self/fd`

This path is hookable. If Frida intercepts `fopen` or `read`, it can feed this scanner whatever it wants.

### Syscall Scanning

Identical scans to the libc path, but every I/O operation goes through inline assembly `svc #0` (ARM64) / `syscall` (x86\_64) rather than libc wrappers. Directory listing uses a raw `getdents64` syscall instead of `opendir`/`readdir`. Even the line-reading loop calls `sc_read` directly.

The point is not that this path is harder to hook — kprobes in a kernel driver catches raw SVC just as well as libc wrappers. The point is that if libc is hooked but the kernel is not, the two paths diverge: libc scan returns CLEAN, syscall scan returns DETECTED. That divergence is itself evidence of compromise, independent of what either scan found.

### Memory Integrity

Two sub-checks that do not go through `/proc` at all:

**ELF disk-vs-memory checksum.** Parses libc's section headers, identifies executable sections (`SHF_EXECINSTR`), and computes a byte-sum of each section in two ways: by reading the on-disk `.so` file (via raw syscalls so the read path cannot be intercepted by a libc hook), and by `memcpy`ing from the live mapped address. Frida writes trampolines into libc's `.text` — a few bytes per hooked function — so the checksums diverge when hooks are present.

The load base is taken as the lowest mapped address for libc (the `r--p` entry at file offset 0). Since libc is a PIC shared library, `sh_addr` in the section header is the offset from the load base, so `base + sh_addr` gives the correct live address even though libc's mapping has five or six VMA entries with different permissions.

**Trampoline prologue scan.** Uses `dlopen(RTLD_NOLOAD)` + `dlsym` to get the live address of a set of commonly-hooked functions (`open`, `read`, `write`, `mmap`, `dlopen`, `dlsym`, `pthread_create`), then reads the first 8 bytes at each address and checks for the Frida/Dobby absolute jump pattern:

```
LDR X17, #8    ; 0x58000051
BR  X17        ; 0xD61F0220
```

followed by an 8-byte absolute target address. A plain `B` (unconditional branch) is also flagged since some inline hookers use a relative branch to a nearby stub.

---

## Architecture

```
app/src/main/
    cpp/
        hook_detector.cpp    -- all detection logic (~700 lines)
        CMakeLists.txt
    java/com/electrondefuser/hookspace/
        HookDetector.kt      -- JNI wrapper (object, 3 external functions)
        MainActivity.kt      -- Compose UI
```

The native library exposes three JNI functions:

```kotlin
HookDetector.scanWithLibc(): String
HookDetector.scanWithSyscall(): String
HookDetector.scanMemoryIntegrity(): String
```

Each returns a multiline string with one result per sub-check. The UI parses `CLEAN` / `DETECTED` / `ERROR` tokens from the output and renders per-check badges. An overall badge at the top of the results section reflects the worst status across all selected methods.

The inline assembly syscall stubs are defined at the top of `hook_detector.cpp` before any function that uses them. This matters because `readLine` in the syscall path calls `sc_read` directly — if the stubs were defined later in the file, it would silently fall back to the libc `syscall()` wrapper and defeat the whole point.

---

## Build

Requirements:

- Android Studio Hedgehog or newer
- NDK r25 or newer
- AGP 8.5.1 (AGP 8.6.0 breaks Android Studio sync as of the time of writing — stay on 8.5.1)
- compileSdk / targetSdk 34
- minSdk 33

The NDK build targets `arm64-v8a` and `x86_64`. The inline assembly has separate paths for ARM64, x86\_64, and ARMv7 (ARMv7 included for completeness but not in the current ABI filter).

Clone and open in Android Studio, or build from the command line:

```bash
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

---

## Bypass

See `KERNEL_BYPASS.md` for a full writeup on bypassing all three detection methods using a kernel module. The short version:

- kprobes on `openat` / `read` / `close` / `getdents64` intercept and sanitize `/proc` reads. This defeats both the libc scan path and the syscall scan path, because kprobes fires on kernel entry regardless of how the syscall was issued from userspace.
- PTE manipulation marks libc `.text` pages not-present during the scan window. A page fault handler serves pre-loaded clean bytes (read from disk before injection) for any `memcpy` or pointer dereference. This defeats the ELF checksum and trampoline scan.
- The two mechanisms together cover everything except timing-based checks and remote attestation, neither of which this app implements.

---

## References

- [darvincisec/DetectFrida](https://github.com/darvincisec/DetectFrida) — thread name scanning and the disk-vs-memory checksum concept
- Linux `kprobes` documentation — `Documentation/trace/kprobes.rst`
- ARM Architecture Reference Manual — A64 instruction set, for trampoline pattern decoding
