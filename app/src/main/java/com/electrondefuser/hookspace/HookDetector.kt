package com.electrondefuser.hookspace

object HookDetector {
    init {
        System.loadLibrary("hookdetector")
    }

    /** Scans /proc via libc (fopen, readdir, read, readlink…) — hookable by Frida. */
    external fun scanWithLibc(): String

    /** Same scans via raw inline-asm SVC — bypasses any hooked libc. */
    external fun scanWithSyscall(): String

    /** ELF disk-vs-memory checksum + function prologue trampoline scan. */
    external fun scanMemoryIntegrity(): String
}
