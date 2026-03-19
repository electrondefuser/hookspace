/**
 * hook_detector.cpp
 *
 * Three independent detection methods exposed to Kotlin:
 *
 *  scanWithLibc()        — scans /proc via libc (fopen, readdir, open…)
 *  scanWithSyscall()     — identical scans via raw inline-asm SVC/SYSCALL
 *  scanMemoryIntegrity() — ELF disk-vs-memory checksum + prologue trampoline
 *
 * Running libc + syscall together lets you detect a hooked libc:
 * libc returns CLEAN while syscall returns DETECTED → libc is compromised.
 */

#include <jni.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <android/log.h>

#define TAG "HookDetector"

#if defined(__aarch64__)
#define SYSCALL_INSTR "svc #0"
#define NR_REG        "x8"
#define RET_REG       "x0"
#define CLOBBERS      "memory", "cc"

static __attribute__((always_inline)) long _sc0(long nr) {
    register long _nr __asm__(NR_REG) = nr;
    register long _r0 __asm__(RET_REG);
    __asm__ __volatile__(SYSCALL_INSTR : "=r"(_r0) : "r"(_nr) : CLOBBERS);
    return _r0;
}
static __attribute__((always_inline)) long _sc1(long nr, long a) {
    register long _nr __asm__(NR_REG) = nr;
    register long _r0 __asm__(RET_REG) = a;
    __asm__ __volatile__(SYSCALL_INSTR : "=r"(_r0) : "r"(_nr),"0"(_r0) : CLOBBERS);
    return _r0;
}
static __attribute__((always_inline)) long _sc3(long nr, long a, long b, long c) {
    register long _nr __asm__(NR_REG) = nr;
    register long _r0 __asm__(RET_REG) = a;
    register long _r1 __asm__("x1") = b;
    register long _r2 __asm__("x2") = c;
    __asm__ __volatile__(SYSCALL_INSTR : "=r"(_r0)
        : "r"(_nr),"0"(_r0),"r"(_r1),"r"(_r2) : CLOBBERS);
    return _r0;
}
static __attribute__((always_inline)) long _sc4(long nr, long a, long b, long c, long d) {
    register long _nr __asm__(NR_REG) = nr;
    register long _r0 __asm__(RET_REG) = a;
    register long _r1 __asm__("x1") = b;
    register long _r2 __asm__("x2") = c;
    register long _r3 __asm__("x3") = d;
    __asm__ __volatile__(SYSCALL_INSTR : "=r"(_r0)
        : "r"(_nr),"0"(_r0),"r"(_r1),"r"(_r2),"r"(_r3) : CLOBBERS);
    return _r0;
}

#elif defined(__x86_64__)

static __attribute__((always_inline)) long _sc0(long nr) {
    long r; __asm__ __volatile__("syscall"
        :"=a"(r):"a"(nr):"memory","rcx","r11"); return r;
}
static __attribute__((always_inline)) long _sc1(long nr, long a) {
    long r; __asm__ __volatile__("syscall"
        :"=a"(r):"a"(nr),"D"(a):"memory","rcx","r11"); return r;
}
static __attribute__((always_inline)) long _sc3(long nr, long a, long b, long c) {
    long r; __asm__ __volatile__("syscall"
        :"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c):"memory","rcx","r11"); return r;
}
static __attribute__((always_inline)) long _sc4(long nr, long a, long b, long c, long d) {
    long r; register long r10 __asm__("r10") = d;
    __asm__ __volatile__("syscall"
        :"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10):"memory","rcx","r11"); return r;
}

#elif defined(__arm__)

static __attribute__((always_inline)) long _sc0(long nr) {
    register long r7 __asm__("r7") = nr, r0 __asm__("r0");
    __asm__ __volatile__("svc #0":"=r"(r0):"r"(r7):"memory"); return r0;
}
static __attribute__((always_inline)) long _sc1(long nr, long a) {
    register long r7 __asm__("r7") = nr, r0 __asm__("r0") = a;
    __asm__ __volatile__("svc #0":"=r"(r0):"r"(r7),"0"(r0):"memory"); return r0;
}
static __attribute__((always_inline)) long _sc3(long nr, long a, long b, long c) {
    register long r7 __asm__("r7") = nr;
    register long r0 __asm__("r0") = a, r1 __asm__("r1") = b, r2 __asm__("r2") = c;
    __asm__ __volatile__("svc #0":"=r"(r0):"r"(r7),"0"(r0),"r"(r1),"r"(r2):"memory"); return r0;
}
static __attribute__((always_inline)) long _sc4(long nr, long a, long b, long c, long d) {
    register long r7 __asm__("r7") = nr;
    register long r0 __asm__("r0") = a, r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c, r3 __asm__("r3") = d;
    __asm__ __volatile__("svc #0":"=r"(r0):"r"(r7),"0"(r0),"r"(r1),"r"(r2),"r"(r3):"memory");
    return r0;
}

#else  // unsupported — best-effort via libc
static long _sc0(long nr)                         { return syscall(nr); }
static long _sc1(long nr,long a)                  { return syscall(nr,a); }
static long _sc3(long nr,long a,long b,long c)    { return syscall(nr,a,b,c); }
static long _sc4(long nr,long a,long b,long c,long d){ return syscall(nr,a,b,c,d); }
#endif

// Typed raw wrappers
static inline int     sc_open  (const char* p,int fl)                { return (int)_sc4(SYS_openat,AT_FDCWD,(long)p,fl,0); }
static inline ssize_t sc_read  (int fd,void* b,size_t n)             { return (ssize_t)_sc3(SYS_read,fd,(long)b,(long)n); }
static inline int     sc_close (int fd)                              { return (int)_sc1(SYS_close,fd); }
static inline ssize_t sc_readlink(const char* p,char* b,size_t n)    { return (ssize_t)_sc4(SYS_readlinkat,AT_FDCWD,(long)p,(long)b,(long)n); }
static inline off_t   sc_lseek (int fd,off_t o,int w)                { return (off_t)_sc3(SYS_lseek,fd,(long)o,w); }

// getdents64 for raw directory iteration
struct sc_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[1];
};
static inline long sc_getdents64(int fd, void* buf, size_t n){
    return _sc3(SYS_getdents64, fd, (long)buf, (long)n);
}

// Raw single-byte line reader
static ssize_t sc_readline(int fd, char* buf, size_t max) {
    size_t n = 0; char c;
    while (n < max - 1) {
        if (sc_read(fd, &c, 1) <= 0) return n == 0 ? -1 : (ssize_t)n;
        if (c == '\n') break;
        buf[n++] = c;
    }
    buf[n] = '\0';
    return (ssize_t)n;
}

// ════════════════════════════════════════════════════════════════
//  §1  SHARED CONSTANTS
// ════════════════════════════════════════════════════════════════

static const char* const HOOK_WORDS[] = {
    "frida","gadget","xposed","substrate",
    "magisk","lsposed","edxposed","zygisk","linjector",
    nullptr
};
static const char* const FRIDA_THREADS[] = {
    "gum-js-loop","gmain","gdbus","pool-frida","linjector",
    nullptr
};

static bool strContainsLower(const char* hay, const char* needle) {
    // simple case-insensitive search
    size_t nlen = strlen(needle);
    for (size_t i = 0; hay[i]; i++) {
        bool m = true;
        for (size_t j = 0; j < nlen; j++) {
            if (tolower((unsigned char)hay[i+j]) != needle[j]) { m = false; break; }
        }
        if (m) return true;
    }
    return false;
}
static bool lineHasHookWord(const char* line) {
    for (int i = 0; HOOK_WORDS[i]; i++)
        if (strContainsLower(line, HOOK_WORDS[i])) return true;
    return false;
}
static bool lineHasFridaThread(const char* line) {
    for (int i = 0; FRIDA_THREADS[i]; i++)
        if (strContainsLower(line, FRIDA_THREADS[i])) return true;
    return false;
}

// ════════════════════════════════════════════════════════════════
//  §2  LIBC-BASED SCANS  (uses fopen / readdir / read / readlink)
// ════════════════════════════════════════════════════════════════

static std::string libc_scanMaps() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return "ERROR: fopen failed";
    char line[512]; std::vector<std::string> hits;
    while (fgets(line, sizeof(line), f))
        if (lineHasHookWord(line)) hits.push_back(std::string(line));
    fclose(f);
    if (hits.empty()) return "CLEAN";
    std::string r = "DETECTED\n";
    for (auto& h : hits) r += "  " + h;
    return r;
}

static std::string libc_scanThreads() {
    DIR* dir = opendir("/proc/self/task");
    if (!dir) return "ERROR: opendir failed";
    std::vector<std::string> hits;
    struct dirent* ent;
    while ((ent = readdir(dir))) {
        if (ent->d_name[0] == '.') continue;
        char path[128]; snprintf(path, sizeof(path),
            "/proc/self/task/%s/status", ent->d_name);
        FILE* f = fopen(path, "r");
        if (!f) continue;
        char line[256] = {};
        fgets(line, sizeof(line), f);  // first line: "Name:\t<name>"
        fclose(f);
        if (lineHasFridaThread(line))
            hits.push_back("tid=" + std::string(ent->d_name) + " " + line);
    }
    closedir(dir);
    if (hits.empty()) return "CLEAN";
    std::string r = "DETECTED — Frida threads\n";
    for (auto& h : hits) r += "  " + h;
    return r;
}

static std::string libc_scanFd() {
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return "ERROR: opendir failed";
    std::vector<std::string> hits;
    struct dirent* ent;
    char buf[512];
    while ((ent = readdir(dir))) {
        std::string p = std::string("/proc/self/fd/") + ent->d_name;
        ssize_t n = readlink(p.c_str(), buf, sizeof(buf)-1);
        if (n > 0) {
            buf[n] = '\0';
            if (lineHasHookWord(buf)) hits.push_back(std::string(buf));
        }
    }
    closedir(dir);
    if (hits.empty()) return "CLEAN";
    std::string r = "DETECTED\n";
    for (auto& h : hits) r += "  fd -> " + h + "\n";
    return r;
}

// Check: perms field has both w and x set AND line has a .so path
// Normal system libs are r-xp — having rwx means code was patched in-place
static bool lineIsRwxSo(const char* line) {
    // format: addr-addr perms offset dev inode [path]
    // perms is the second token, e.g. "rwxp"
    const char* p = strchr(line, ' ');
    if (!p) return false;
    p++; // skip space, now at perms
    // need at least 4 chars for perms
    if (strlen(p) < 4) return false;
    bool isW = (p[1] == 'w');
    bool isX = (p[2] == 'x');
    if (!isW || !isX) return false;
    // must have a .so path on the line
    return strstr(line, ".so") != nullptr;
}

static std::string libc_scanRwxPages() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return "ERROR: fopen failed";
    char line[512];
    std::vector<std::string> hits;
    while (fgets(line, sizeof(line), f))
        if (lineIsRwxSo(line)) hits.push_back(std::string(line));
    fclose(f);
    if (hits.empty()) return "CLEAN";
    std::string r = "DETECTED — rwx pages in .so mappings\n";
    for (auto& h : hits) r += "  " + h;
    return r;
}

static std::string libc_tracerPid() {
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return "ERROR: fopen failed";
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            return pid ? "DETECTED: TracerPid=" + std::to_string(pid)
                       : "CLEAN: TracerPid=0";
        }
    }
    fclose(f);
    return "ERROR: TracerPid not found";
}

// ════════════════════════════════════════════════════════════════
//  §3  SYSCALL-BASED SCANS  (svc #0 / syscall — no libc at all)
// ════════════════════════════════════════════════════════════════

static std::string sc_scanMaps() {
    int fd = sc_open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "ERROR: open syscall failed";
    std::vector<std::string> hits;
    char line[512];
    // read char-by-char via raw syscall to build lines
    size_t n = 0; char c;
    while (sc_read(fd, &c, 1) > 0) {
        if (c == '\n' || n == sizeof(line)-1) {
            line[n] = '\0';
            if (lineHasHookWord(line)) hits.push_back(std::string(line));
            n = 0;
        } else { line[n++] = c; }
    }
    sc_close(fd);
    if (hits.empty()) return "CLEAN";
    std::string r = "DETECTED\n";
    for (auto& h : hits) r += "  " + h + "\n";
    return r;
}

static std::string sc_scanThreads() {
    int dir_fd = sc_open("/proc/self/task", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) return "ERROR: open syscall failed";

    std::vector<std::string> hits;
    char dents_buf[2048];
    long nread;
    while ((nread = sc_getdents64(dir_fd, dents_buf, sizeof(dents_buf))) > 0) {
        long pos = 0;
        while (pos < nread) {
            auto* d = reinterpret_cast<sc_dirent64*>(dents_buf + pos);
            const char* name = d->d_name;
            pos += d->d_reclen;
            if (name[0] == '.') continue;

            char path[128];
            // build /proc/self/task/<tid>/status
            size_t plen = 0;
            const char* base = "/proc/self/task/";
            while (base[plen]) path[plen] = base[plen], plen++;
            for (size_t j = 0; name[j]; j++) path[plen++] = name[j];
            const char* suf = "/status";
            for (size_t j = 0; suf[j]; j++) path[plen++] = suf[j];
            path[plen] = '\0';

            int sfd = sc_open(path, O_RDONLY | O_CLOEXEC);
            if (sfd < 0) continue;
            char line[256] = {};
            sc_readline(sfd, line, sizeof(line));
            sc_close(sfd);
            if (lineHasFridaThread(line))
                hits.push_back("tid=" + std::string(name) + " " + line);
        }
    }
    sc_close(dir_fd);
    if (hits.empty()) return "CLEAN";
    std::string r = "DETECTED — Frida threads\n";
    for (auto& h : hits) r += "  " + h + "\n";
    return r;
}

static std::string sc_scanFd() {
    int dir_fd = sc_open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) return "ERROR: open syscall failed";

    std::vector<std::string> hits;
    char dents_buf[2048];
    long nread;
    while ((nread = sc_getdents64(dir_fd, dents_buf, sizeof(dents_buf))) > 0) {
        long pos = 0;
        while (pos < nread) {
            auto* d = reinterpret_cast<sc_dirent64*>(dents_buf + pos);
            const char* name = d->d_name;
            pos += d->d_reclen;
            if (name[0] == '.') continue;

            char lpath[128] = "/proc/self/fd/";
            strncat(lpath, name, sizeof(lpath) - strlen(lpath) - 1);

            char target[512] = {};
            ssize_t len = sc_readlink(lpath, target, sizeof(target)-1);
            if (len > 0) {
                target[len] = '\0';
                if (lineHasHookWord(target)) hits.push_back(std::string(target));
            }
        }
    }
    sc_close(dir_fd);
    if (hits.empty()) return "CLEAN";
    std::string r = "DETECTED\n";
    for (auto& h : hits) r += "  fd -> " + h + "\n";
    return r;
}

static std::string sc_scanRwxPages() {
    int fd = sc_open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "ERROR: open syscall failed";
    std::vector<std::string> hits;
    char line[512];
    size_t n = 0; char c;
    while (sc_read(fd, &c, 1) > 0) {
        if (c == '\n' || n == sizeof(line) - 1) {
            line[n] = '\0';
            if (lineIsRwxSo(line)) hits.push_back(std::string(line));
            n = 0;
        } else { line[n++] = c; }
    }
    sc_close(fd);
    if (hits.empty()) return "CLEAN";
    std::string r = "DETECTED — rwx pages in .so mappings\n";
    for (auto& h : hits) r += "  " + h + "\n";
    return r;
}

static std::string sc_tracerPid() {
    int fd = sc_open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "ERROR: open syscall failed";
    char line[256];
    ssize_t r;
    // scan lines via raw read
    while (sc_readline(fd, line, sizeof(line)) >= 0) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            sc_close(fd);
            return pid ? "DETECTED: TracerPid=" + std::to_string(pid)
                       : "CLEAN: TracerPid=0";
        }
    }
    sc_close(fd);
    return "ERROR: TracerPid not found";
}

// ════════════════════════════════════════════════════════════════
//  §4  MEMORY INTEGRITY
//      ELF disk-vs-memory checksum (file I/O via raw syscalls)
//      + function prologue trampoline scan via dlsym
// ════════════════════════════════════════════════════════════════

#if __LP64__
using Elf_Ehdr = Elf64_Ehdr; using Elf_Shdr = Elf64_Shdr;
#else
using Elf_Ehdr = Elf32_Ehdr; using Elf_Shdr = Elf32_Shdr;
#endif

static std::string findLibPath(const std::string& name, uintptr_t& baseOut) {
    baseOut = 0;
    int fd = sc_open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "";
    char line[512]; size_t n = 0; char c;
    std::string found;
    uintptr_t lowest = UINTPTR_MAX;
    while (sc_read(fd, &c, 1) > 0) {
        if (c == '\n' || n == sizeof(line)-1) {
            line[n] = '\0'; n = 0;
            if (strContainsLower(line, name.c_str())) {
                uintptr_t s, e; char perms[8], path[256] = {};
                if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %255[^\n]",
                           &s, &e, perms, path) >= 3) {
                    const char* p = path; while (*p==' ') p++;
                    if (s < lowest) { lowest=s; baseOut=s; found=p; }
                }
            }
        } else { line[n++] = c; }
    }
    sc_close(fd);
    return found;
}

static uint64_t byteSum(const uint8_t* b, size_t n) {
    uint64_t s = 0; for (size_t i = 0; i < n; i++) s += b[i]; return s;
}

static std::string elfChecksumCompare(const std::string& libName) {
    uintptr_t base = 0;
    std::string path = findLibPath(libName, base);
    if (path.empty()) return "SKIP: not found";

    int fd = sc_open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "SKIP: cannot open " + path;

    Elf_Ehdr ehdr;
    if (sc_read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr) ||
        ehdr.e_ident[0] != ELFMAG0) {
        sc_close(fd); return "ERROR: bad ELF";
    }
    sc_lseek(fd, (off_t)ehdr.e_shoff, SEEK_SET);

    std::vector<std::string> tampered;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf_Shdr sh;
        if (sc_read(fd, &sh, sizeof(sh)) != sizeof(sh)) break;
        if (!(sh.sh_flags & SHF_EXECINSTR) || sh.sh_size == 0) continue;
        if (sh.sh_size > 8*1024*1024) continue;

        std::vector<uint8_t> disk(sh.sh_size), mem(sh.sh_size);
        sc_lseek(fd, (off_t)sh.sh_offset, SEEK_SET);
        if (sc_read(fd, disk.data(), sh.sh_size) != (ssize_t)sh.sh_size) continue;
        memcpy(mem.data(), (const uint8_t*)(base + sh.sh_addr), sh.sh_size);

        uint64_t dc = byteSum(disk.data(), sh.sh_size);
        uint64_t mc = byteSum(mem.data(),  sh.sh_size);
        if (dc != mc) {
            char tmp[128];
            snprintf(tmp, sizeof(tmp), "section@0x%lx disk=%llu mem=%llu",
                     (unsigned long)sh.sh_addr,
                     (unsigned long long)dc, (unsigned long long)mc);
            tampered.emplace_back(tmp);
        }
    }
    sc_close(fd);
    if (tampered.empty()) return "CLEAN: " + libName;
    std::string r = "DETECTED in " + libName + "\n";
    for (auto& t : tampered) r += "  " + t + "\n";
    return r;
}

#if defined(__aarch64__)
static bool isTrampoline(const uint8_t* p) {
    uint32_t i0, i1; memcpy(&i0,p,4); memcpy(&i1,p+4,4);
    if (((i0&0xFF00001F)==0x58000010)&&((i1&0xFFFFFC1F)==0xD61F0000)) return true;
    if ((i0&0xFC000000)==0x14000000) return true;
    return false;
}
#elif defined(__arm__)
static bool isTrampoline(const uint8_t* p) {
    uint32_t i0; memcpy(&i0,p,4);
    return i0==0xE51FF004 || (i0&0xFF000000)==0xEA000000;
}
#else
static bool isTrampoline(const uint8_t*) { return false; }
#endif

static std::string trampolineScan(const std::string& libName) {
    void* h = dlopen(libName.c_str(), RTLD_NOW | RTLD_NOLOAD);
    if (!h) return "SKIP: not loaded";
    static const char* FNS[] = {
        "open","openat","read","write","mmap","dlopen","dlsym","pthread_create",nullptr };
    std::vector<std::string> hooked;
    for (int i = 0; FNS[i]; i++) {
        void* s = dlsym(h, FNS[i]); if (!s) continue;
        auto* p = reinterpret_cast<const uint8_t*>(s);
        if (isTrampoline(p)) {
            char hex[32]; uint32_t w; memcpy(&w,p,4);
            snprintf(hex,sizeof(hex),"0x%08X",w);
            hooked.push_back(std::string(FNS[i])+"["+hex+"]");
        }
    }
    dlclose(h);
    if (hooked.empty()) return "CLEAN: " + libName;
    std::string r = "DETECTED in " + libName + "\n";
    for (auto& fn : hooked) r += "  " + fn + "\n";
    return r;
}

// ════════════════════════════════════════════════════════════════
//  JNI EXPORTS
// ════════════════════════════════════════════════════════════════
extern "C" {

// Scans using libc functions — hookable by Frida
JNIEXPORT jstring JNICALL
Java_com_electrondefuser_hookspace_HookDetector_scanWithLibc(JNIEnv* env, jobject) {
    std::string r;
    r += "[maps]      " + libc_scanMaps()      + "\n";
    r += "[rwx-pages] " + libc_scanRwxPages() + "\n";
    r += "[tracerpid] " + libc_tracerPid()    + "\n";
    r += "[threads]   " + libc_scanThreads()  + "\n";
    r += "[fd]        " + libc_scanFd()       + "\n";
    return env->NewStringUTF(r.c_str());
}

// Identical scans via inline-asm SVC — bypasses hooked libc entirely
JNIEXPORT jstring JNICALL
Java_com_electrondefuser_hookspace_HookDetector_scanWithSyscall(JNIEnv* env, jobject) {
    std::string r;
    r += "[maps]      " + sc_scanMaps()      + "\n";
    r += "[rwx-pages] " + sc_scanRwxPages() + "\n";
    r += "[tracerpid] " + sc_tracerPid()    + "\n";
    r += "[threads]   " + sc_scanThreads()  + "\n";
    r += "[fd]        " + sc_scanFd()       + "\n";
    return env->NewStringUTF(r.c_str());
}

// ELF checksum + prologue trampoline scan
JNIEXPORT jstring JNICALL
Java_com_electrondefuser_hookspace_HookDetector_scanMemoryIntegrity(JNIEnv* env, jobject) {
    std::string r;
    r += "[elf-csum libc]    " + elfChecksumCompare("libc.so") + "\n";
    r += "[trampoline libc]  " + trampolineScan("libc.so")     + "\n";
    r += "[trampoline libdl] " + trampolineScan("libdl.so")    + "\n";
    return env->NewStringUTF(r.c_str());
}

} // extern "C"
