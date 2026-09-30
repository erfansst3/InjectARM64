#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <utility>
#include <set>
#include <mutex>

#define TAG "InjectARM64"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG,__VA_ARGS__)

#ifndef SYS_openat2
#define SYS_openat2 437
#endif

using MSHookFunctionFn = void(*)(void*, void*, void**);
using OpenFn = int(*)(const char*, int, ...);
using OpenAtFn = int(*)(int, const char*, int, ...);
using Open2Fn = int(*)(const char*, int);
using OpenAt2Fn = int(*)(int, const char*, int);
using FopenFn = FILE*(*)(const char*, const char*);
using IoctlFn = int(*)(int, unsigned long, void*);
using SyscallFn = long(*)(long, long, long, long, long, long, long);
using CloseFn = int(*)(int);
using SystemFn = int(*)(const char*);
using PopenFn = FILE*(*)(const char*, const char*);
using ExecveFn = int(*)(const char*, char* const[], char* const[]);
using FstatFn = int(*)(int, struct stat*);
using MmapFn = void*(*)(void*, size_t, int, int, int, off_t);

// تایپ‌های توابع خروج و توقف
using ExitFn = void(*)(int);
using _ExitFn = void(*)(int);
using AbortFn = void(*)(void);
using KillFn = int(*)(pid_t, int);
using RaiseFn = int(*)(int);

static MSHookFunctionFn gHook;
static OpenFn gOpen;
static OpenAtFn gOpenAt;
static Open2Fn gOpen2;
static OpenAt2Fn gOpenAt2;
static Open2Fn gOpen64_2;
static OpenAt2Fn gOpenAt64_2;
static FopenFn gFopen;
static IoctlFn gIoctl;
static SyscallFn gSyscall;
static CloseFn gClose;
static SystemFn gSystem;
static PopenFn gPopen;
static ExecveFn gExecve;
static FstatFn gFstat;
static FstatFn gFstat64;
static MmapFn gMmap;
static MmapFn gMmap64;

// پوینتر توابع اصلی خروج
static ExitFn gExit;
static _ExitFn g_Exit;
static AbortFn gAbort;
static KillFn gKill;
static RaiseFn gRaise;

static std::atomic<int> gInstalled{0}, gGspaceFound{0};
static std::atomic<int> hOpenAt{0}, hOpen{0}, hFopen{0}, hIoctl{0}, hSyscall{0};
static std::atomic<int> hSystem{0}, hPopen{0}, hExecve{0};

// محافظ محلی نخ جهت جلوگیری از حلقه بازگشتی بی‌نهایت و کرش
static thread_local bool g_inside_hook = false;

// مدیریت و ثبت لیست FDهای فیک
static std::set<int> g_fake_fds;
static std::mutex g_fds_mutex;
static std::string marker;

static void registerFakeFd(int fd) {
    if (fd >= 0) {
        std::lock_guard<std::mutex> lock(g_fds_mutex);
        g_fake_fds.insert(fd);
    }
}

static void unregisterFakeFd(int fd) {
    if (fd >= 0) {
        std::lock_guard<std::mutex> lock(g_fds_mutex);
        g_fake_fds.erase(fd);
    }
}

static bool isFakeFd(int fd) {
    if (fd < 0) return false;
    std::lock_guard<std::mutex> lock(g_fds_mutex);
    return g_fake_fds.find(fd) != g_fake_fds.end();
}

struct HookRecord { void* addr; void* orig; void* repl; };
static HookRecord gHookRecords[48];
static int gHookRecordCount = 0;

struct GSpaceModule { uintptr_t base = 0; const ElfW(Phdr)* dynamicPhdr = nullptr; };

static bool findGSpaceModule(GSpaceModule& out) {
    auto cb = [](dl_phdr_info* i, size_t, void* p)->int {
        auto* m = (GSpaceModule*)p;
        if (!i->dlpi_name || !strstr(i->dlpi_name, "libgspace_64.so")) return 0;
        m->base = (uintptr_t)i->dlpi_addr;
        for (int n = 0; n < i->dlpi_phnum; n++) if (i->dlpi_phdr[n].p_type == PT_DYNAMIC) { m->dynamicPhdr = &i->dlpi_phdr[n]; break; }
        return 1;
    };
    dl_iterate_phdr(cb, &out);
    return out.base && out.dynamicPhdr;
}

static uintptr_t dynPtr(uintptr_t b, ElfW(Addr) v) { return b + (uintptr_t)v; }
static size_t sysvHashSymbolCount(const ElfW(Word)* h) { return h ? (size_t)h[1] : 0; }

static size_t gnuHashSymbolCount(const uint32_t* h) {
    if (!h) return 0;
    uint32_t nb = h[0], so = h[1], bs = h[2];
    if (!nb) return so;
    const uintptr_t* bloom = (const uintptr_t*)(h + 4);
    const uint32_t* buckets = (const uint32_t*)bloom + bs * (sizeof(ElfW(Addr)) / 4);
    const uint32_t* chains = buckets + nb;
    uint32_t max = so;
    for (uint32_t i = 0; i < nb; i++) {
        uint32_t x = buckets[i];
        if (x < so) continue;
        while (x >= so) {
            if (x > max) max = x;
            if (chains[x - so] & 1) break;
            if (++x > 10000000U) return 0;
        }
    }
    return (size_t)max + 1;
}

static uintptr_t findGSpaceExport(const char* name) {
    GSpaceModule m;
    if (!findGSpaceModule(m)) return 0;
    gGspaceFound = 1;
    auto* d = (ElfW(Dyn)*)(m.base + m.dynamicPhdr->p_vaddr);
    ElfW(Sym)* st = nullptr; const char* str = nullptr; size_t sz = 0; const ElfW(Word)* sh = nullptr; const uint32_t* gh = nullptr;
    for (; d->d_tag != DT_NULL; d++) switch (d->d_tag) {
        case DT_SYMTAB: st = (ElfW(Sym)*)dynPtr(m.base, d->d_un.d_ptr); break;
        case DT_STRTAB: str = (const char*)dynPtr(m.base, d->d_un.d_ptr); break;
        case DT_STRSZ: sz = (size_t)d->d_un.d_val; break;
        case DT_HASH: sh = (const ElfW(Word)*)dynPtr(m.base, d->d_un.d_ptr); break;
        case DT_GNU_HASH: gh = (const uint32_t*)dynPtr(m.base, d->d_un.d_ptr); break;
    }
    if (!st || !str || !sz) return 0;
    void* h = dlopen("libgspace_64.so", RTLD_NOW | RTLD_NOLOAD);
    if (h) { void* p = dlsym(h, name); dlclose(h); if (p) return (uintptr_t)p; }
    size_t n = sysvHashSymbolCount(sh); if (!n) n = gnuHashSymbolCount(gh); if (!n) return 0;
    for (size_t i = 0; i < n; i++) {
        auto& s = st[i];
        if (!s.st_name || s.st_name >= sz || s.st_shndx == SHN_UNDEF || ELF64_ST_TYPE(s.st_info) != STT_FUNC) continue;
        if (!strcmp(str + s.st_name, name)) return m.base + (uintptr_t)s.st_value;
    }
    return 0;
}

// فیلتر اختصاصی kossher و smaps/maps
static bool isKossherPath(const char* p) {
    if (!p) return false;
    if (strstr(p, "kossher") || strstr(p, "smaps") || strstr(p, "maps")) {
        return true;
    }
    return false;
}

static bool isWritableExecutableLine(const std::string& line) {
    size_t space1 = line.find(' ');
    if (space1 != std::string::npos && space1 + 4 <= line.length()) {
        std::string perm = line.substr(space1 + 1, 4);
        if (perm.find('w') != std::string::npos && perm.find('x') != std::string::npos) {
            return true;
        }
    }
    return false;
}

static std::string getmaps() {
    bool old_inside = g_inside_hook;
    g_inside_hook = true;

    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY, 0);
    if (fd < 0) {
        g_inside_hook = old_inside;
        return "";
    }

    char buf[8192];
    std::string s, out, line;
    ssize_t n;
    while ((n = syscall(SYS_read, fd, buf, sizeof(buf))) > 0) {
        s.append(buf, n);
    }
    syscall(SYS_close, fd);
    g_inside_hook = old_inside;

    size_t p = 0;
    while (p < s.size()) {
        size_t e = s.find('\n', p);
        if (e == std::string::npos) e = s.size();
        line = s.substr(p, e - p + 1);
        p = e + 1;

        if (isWritableExecutableLine(line)) {
            continue;
        }

        out += line;
    }
    return out;
}

std::string getsmaps() {
    bool old_inside = g_inside_hook;
    g_inside_hook = true;

    int fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/smaps", O_RDONLY, 0);
    if (fd < 0) {
        g_inside_hook = old_inside;
        return "";
    }
    char buf[8192];
    std::string s, out, line;
    ssize_t n;
    while ((n = syscall(SYS_read, fd, buf, sizeof(buf))) > 0) s.append(buf, n);
    syscall(SYS_close, fd);
    g_inside_hook = old_inside;

    bool crypto = false;
    size_t p = 0;
    while (p < s.size()) {
        size_t e = s.find('\n', p);
        if (e == std::string::npos) e = s.size();
        line = s.substr(p, e - p + 1);
        p = e + 1;

        if (line.find('-') != std::string::npos)
            crypto = line.find("libcrypto.so") != std::string::npos;

        if (crypto && (line.rfind("Shared_Dirty:", 0) == 0 || line.rfind("Private_Dirty:", 0) == 0))
            continue;

        out += line;
    }
    return out;
}

static std::string getBufferForPath(const char* p) {
    if (!p) return marker;
    if (strstr(p, "smaps")) {
        return getsmaps();
    }
    if (strstr(p, "maps")) {
        return getmaps();
    }
    return marker;
}

static int makeFakeFd(const std::string& d) {
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, "smaps", 1);
    if (fd < 0) return -1;
    size_t n = 0;
    while (n < d.size()) {
        ssize_t w = syscall(SYS_write, fd, d.data() + n, d.size() - n);
        if (w <= 0) { syscall(SYS_close, fd); return -1; }
        n += (size_t)w;
    }
    syscall(SYS_lseek, fd, 0, SEEK_SET);
    registerFakeFd(fd);
    return fd;
#else
    return -1;
#endif
}

static int fakeClose(int fd) {
    unregisterFakeFd(fd);
    return gClose ? gClose(fd) : close(fd);
}

static int fakeOpenAt(int d, const char* p, int f, ...) {
    if (g_inside_hook) {
        if (!gOpenAt) { errno = ENOSYS; return -1; }
        va_list a; va_start(a, f); mode_t m = (f & O_CREAT) ? va_arg(a, int) : 0; va_end(a);
        return gOpenAt(d, p, f, m);
    }
    g_inside_hook = true;

    if (isKossherPath(p) && (f & O_ACCMODE) != O_WRONLY) {
        hOpenAt++;
        int fd = makeFakeFd(getBufferForPath(p));
        if (fd >= 0) {
            LOGI("HOOK openat %s pid=%d fd=%d", p, getpid(), fd);
            g_inside_hook = false;
            return fd;
        }
    }
    if (!gOpenAt) {
        g_inside_hook = false;
        errno = ENOSYS;
        return -1;
    }
    va_list a; va_start(a, f); mode_t m = (f & O_CREAT) ? va_arg(a, int) : 0; va_end(a);
    int res = gOpenAt(d, p, f, m);
    g_inside_hook = false;
    return res;
}

static int fakeOpen(const char* p, int f, ...) {
    if (g_inside_hook) {
        if (!gOpen) { errno = ENOSYS; return -1; }
        va_list a; va_start(a, f); mode_t m = (f & O_CREAT) ? va_arg(a, int) : 0; va_end(a);
        return (f & O_CREAT) ? gOpen(p, f, m) : gOpen(p, f);
    }
    g_inside_hook = true;

    if (isKossherPath(p) && (f & O_ACCMODE) != O_WRONLY) {
        hOpen++;
        int fd = makeFakeFd(getBufferForPath(p));
        if (fd >= 0) {
            LOGI("HOOK open %s pid=%d fd=%d", p, getpid(), fd);
            g_inside_hook = false;
            return fd;
        }
    }
    if (!gOpen) {
        g_inside_hook = false;
        errno = ENOSYS;
        return -1;
    }
    va_list a; va_start(a, f); mode_t m = (f & O_CREAT) ? va_arg(a, int) : 0; va_end(a);
    int res = (f & O_CREAT) ? gOpen(p, f, m) : gOpen(p, f);
    g_inside_hook = false;
    return res;
}

static int fakeOpen2(const char* p, int f) {
    if (g_inside_hook) return gOpen2 ? gOpen2(p, f) : -1;
    g_inside_hook = true;
    if (isKossherPath(p) && (f & O_ACCMODE) != O_WRONLY) {
        hOpen++;
        int fd = makeFakeFd(getBufferForPath(p));
        if (fd >= 0) {
            LOGI("HOOK __open_2 %s pid=%d fd=%d", p, getpid(), fd);
            g_inside_hook = false;
            return fd;
        }
    }
    int res = gOpen2 ? gOpen2(p, f) : -1;
    g_inside_hook = false;
    return res;
}

static int fakeOpenAt2(int d, const char* p, int f) {
    if (g_inside_hook) return gOpenAt2 ? gOpenAt2(d, p, f) : -1;
    g_inside_hook = true;
    if (isKossherPath(p) && (f & O_ACCMODE) != O_WRONLY) {
        hOpenAt++;
        int fd = makeFakeFd(getBufferForPath(p));
        if (fd >= 0) {
            LOGI("HOOK __openat_2 %s pid=%d fd=%d", p, getpid(), fd);
            g_inside_hook = false;
            return fd;
        }
    }
    int res = gOpenAt2 ? gOpenAt2(d, p, f) : -1;
    g_inside_hook = false;
    return res;
}

static FILE* fakeFopen(const char* p, const char* m) {
    if (g_inside_hook) return gFopen ? gFopen(p, m) : nullptr;
    g_inside_hook = true;
    if (isKossherPath(p)) {
        hFopen++;
        int fd = makeFakeFd(getBufferForPath(p));
        if (fd >= 0) {
            LOGI("HOOK fopen %s pid=%d fd=%d", p, getpid(), fd);
            g_inside_hook = false;
            return fdopen(fd, m && *m ? m : "r");
        }
    }
    FILE* res = gFopen ? gFopen(p, m) : nullptr;
    g_inside_hook = false;
    return res;
}

static FILE* fakePopen(const char* command, const char* type) {
    if (g_inside_hook) return gPopen ? gPopen(command, type) : nullptr;
    g_inside_hook = true;
    
    if (isKossherPath(command)) {
        hPopen++;
        int fd = makeFakeFd(getBufferForPath(command));
        if (fd >= 0) {
            LOGI("HOOK popen command=%s pid=%d fd=%d", command, getpid(), fd);
            g_inside_hook = false;
            return fdopen(fd, type && *type ? type : "r");
        }
    }
    
    FILE* res = gPopen ? gPopen(command, type) : nullptr;
    g_inside_hook = false;
    return res;
}

static int fakeSystem(const char* command) {
    if (g_inside_hook) return gSystem ? gSystem(command) : -1;
    g_inside_hook = true;
    
    if (isKossherPath(command)) {
        hSystem++;
        LOGI("HOOK system command=%s pid=%d", command, getpid());
        
        std::string data = getBufferForPath(command);
        printf("%s", data.c_str());
        fflush(stdout);
        
        g_inside_hook = false;
        return 0;
    }
    
    int res = gSystem ? gSystem(command) : -1;
    g_inside_hook = false;
    return res;
}

static int fakeExecve(const char* filename, char* const argv[], char* const envp[]) {
    if (g_inside_hook) return gExecve ? gExecve(filename, argv, envp) : execve(filename, argv, envp);
    g_inside_hook = true;

    bool match = false;
    const char* matched_path = filename;
    if (filename && isKossherPath(filename)) match = true;
    if (!match && argv) {
        for (int i = 0; argv[i] != nullptr; i++) {
            if (isKossherPath(argv[i])) {
                match = true;
                matched_path = argv[i];
                break;
            }
        }
    }

    if (match) {
        hExecve++;
        LOGI("HOOK execve intercepted for kossher pid=%d", getpid());
        
        std::string data = getBufferForPath(matched_path);
        printf("%s", data.c_str());
        fflush(stdout);

        g_inside_hook = false;
        _exit(0);
    }

    int res = gExecve ? gExecve(filename, argv, envp) : execve(filename, argv, envp);
    g_inside_hook = false;
    return res;
}

static int fakeFstat(int fd, struct stat* buf) {
    if (g_inside_hook || fd < 0) {
        return gFstat ? gFstat(fd, buf) : fstat(fd, buf);
    }
    g_inside_hook = true;

    int res = gFstat ? gFstat(fd, buf) : fstat(fd, buf);
    if (res == 0 && buf && isFakeFd(fd)) {
        buf->st_size = 0;
    }

    g_inside_hook = false;
    return res;
}

static void* fakeMmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (g_inside_hook || fd < 0) {
        return gMmap ? gMmap(addr, length, prot, flags, fd, offset) : mmap(addr, length, prot, flags, fd, offset);
    }
    g_inside_hook = true;

    if (isFakeFd(fd)) {
        g_inside_hook = false;
        errno = ENODEV;
        return MAP_FAILED;
    }

    void* res = gMmap ? gMmap(addr, length, prot, flags, fd, offset) : mmap(addr, length, prot, flags, fd, offset);
    g_inside_hook = false;
    return res;
}

static int fakeIoctl(int fd, unsigned long request, void* arg) {
    if (g_inside_hook || fd < 0) {
        return gIoctl ? gIoctl(fd, request, arg) : ioctl(fd, request, arg);
    }
    g_inside_hook = true;
    hIoctl++;

    if (isFakeFd(fd) && request == FIONREAD) {
        if (arg) {
            *reinterpret_cast<int*>(arg) = 0;
        }
        g_inside_hook = false;
        return 0;
    }

    int res = gIoctl ? gIoctl(fd, request, arg) : ioctl(fd, request, arg);
    g_inside_hook = false;
    return res;
}

// ---------------------------------------------------------------------------
// پروکسی توابع خروج و توقف جهت جلوگیری از بسته شدن برنامه
// ---------------------------------------------------------------------------

static void fakeExit(int status) {
    LOGI("HOOK exit intercepted! status=%d pid=%d", status, getpid());
    // عدم خروج از برنامه
}

static void fake_Exit(int status) {
    LOGI("HOOK _exit intercepted! status=%d pid=%d", status, getpid());
    // عدم خروج از برنامه
}

static void fakeAbort() {
    LOGI("HOOK abort intercepted! pid=%d", getpid());
    // عدم خروج از برنامه
}

static int fakeKill(pid_t pid, int sig) {
    // اگر درخواست کشتن همین پردازه با سیگنال‌های کشنده صادر شود
    if ((pid == getpid() || pid == 0 || pid == -1) && 
        (sig == SIGKILL || sig == SIGABRT || sig == SIGSEGV || sig == SIGTERM)) {
        LOGI("HOOK kill intercepted! target pid=%d sig=%d", pid, sig);
        return 0; // گزارش خروجی موفق بدون اجرا
    }
    return gKill ? gKill(pid, sig) : kill(pid, sig);
}

static int fakeRaise(int sig) {
    if (sig == SIGKILL || sig == SIGABRT || sig == SIGSEGV || sig == SIGTERM) {
        LOGI("HOOK raise intercepted! sig=%d pid=%d", sig, getpid());
        return 0; // گزارش خروجی موفق بدون اجرا
    }
    return gRaise ? gRaise(sig) : raise(sig);
}

static long fakeSyscall(long number, long a1, long a2, long a3, long a4, long a5, long a6) {
    if (g_inside_hook) {
        return gSyscall ? gSyscall(number, a1, a2, a3, a4, a5, a6) : syscall(number, a1, a2, a3, a4, a5, a6);
    }
    g_inside_hook = true;

    // رهگیری سیستم‌کال‌های خروج (exit / exit_group)
#ifdef SYS_exit_group
    if (number == SYS_exit_group || number == SYS_exit) {
        LOGI("HOOK syscall exit/exit_group intercepted! nr=%ld", number);
        g_inside_hook = false;
        return 0;
    }
#endif

#ifdef SYS_kill
    if (number == SYS_kill || number == SYS_tgkill) {
        pid_t pid = static_cast<pid_t>(a1);
        int sig = static_cast<int>(a2);
        if ((pid == getpid() || pid == 0) && (sig == SIGKILL || sig == SIGABRT || sig == SIGSEGV || sig == SIGTERM)) {
            LOGI("HOOK syscall kill/tgkill intercepted! sig=%d", sig);
            g_inside_hook = false;
            return 0;
        }
    }
#endif

#ifdef SYS_openat
    if (number == SYS_openat) {
        const char* path = reinterpret_cast<const char*>(a2);
        int flags = static_cast<int>(a3);
        if (isKossherPath(path) && (flags & O_ACCMODE) != O_WRONLY) {
            int fd = makeFakeFd(getBufferForPath(path));
            if (fd >= 0) {
                LOGI("HOOK syscall(SYS_openat) %s pid=%d fd=%d", path, getpid(), fd);
                g_inside_hook = false;
                return fd;
            }
        }
    }
#endif

#ifdef SYS_openat2
    if (number == SYS_openat2) {
        const char* path = reinterpret_cast<const char*>(a2);
        if (isKossherPath(path)) {
            int fd = makeFakeFd(getBufferForPath(path));
            if (fd >= 0) {
                LOGI("HOOK syscall(SYS_openat2) %s pid=%d fd=%d", path, getpid(), fd);
                g_inside_hook = false;
                return fd;
            }
        }
    }
#endif

#ifdef SYS_ioctl
    if (number == SYS_ioctl) {
        int fd = static_cast<int>(a1);
        unsigned long req = static_cast<unsigned long>(a2);
        void* arg = reinterpret_cast<void*>(a3);
        if (isFakeFd(fd) && req == FIONREAD) {
            if (arg) {
                *reinterpret_cast<int*>(arg) = 0;
            }
            g_inside_hook = false;
            return 0;
        }
    }
#endif

#ifdef SYS_mmap
    if (number == SYS_mmap) {
        int fd = static_cast<int>(a5);
        if (isFakeFd(fd)) {
            g_inside_hook = false;
            errno = ENODEV;
            return -ENODEV;
        }
    }
#endif

    long ret = gSyscall ? gSyscall(number, a1, a2, a3, a4, a5, a6) : syscall(number, a1, a2, a3, a4, a5, a6);
    g_inside_hook = false;
    return ret;
}

static void* gLibc;
static void* gOpenAddr;
static void* gOpenAtAddr;
static void* gOpen2Addr;
static void* gOpenAt2Addr;
static void* gOpen64_2Addr;
static void* gOpenAt64_2Addr;
static void* gFopenAddr;
static void* gIoctlAddr;
static void* gSyscallAddr;
static void* gSystemAddr;
static void* gPopenAddr;
static void* gExecveAddr;
static void* gFstatAddr;
static void* gFstat64Addr;
static void* gMmapAddr;
static void* gMmap64Addr;

static void* gExitAddr;
static void* g_ExitAddr;
static void* gAbortAddr;
static void* gKillAddr;
static void* gRaiseAddr;

static bool hookLibcSymbol(MSHookFunctionFn h, const char* n, void* repl, void** orig, void** addrStore) {
    if (!gLibc || !n || !orig) return false;
    void* p = dlsym(gLibc, n);
    if (!p) return false;
    if (addrStore) *addrStore = p;

    for (int i = 0; i < gHookRecordCount; i++) {
        if (gHookRecords[i].addr == p) {
            *orig = gHookRecords[i].orig;
            return *orig != nullptr;
        }
    }

    void* saved = nullptr;
    h(p, repl, &saved);
    if (!saved) return false;
    if (gHookRecordCount < (int)(sizeof(gHookRecords) / sizeof(gHookRecords[0]))) {
        gHookRecords[gHookRecordCount++] = {p, saved, repl};
    }
    *orig = saved;
    return true;
}

static void libcScan() {
    gLibc = dlopen("libc.so", RTLD_NOW);
    if (!gLibc) return;

    hookLibcSymbol(gHook, "open", (void*)fakeOpen, (void**)&gOpen, &gOpenAddr);
    hookLibcSymbol(gHook, "openat", (void*)fakeOpenAt, (void**)&gOpenAt, &gOpenAtAddr);
    hookLibcSymbol(gHook, "__open_2", (void*)fakeOpen2, (void**)&gOpen2, &gOpen2Addr);
    hookLibcSymbol(gHook, "__openat_2", (void*)fakeOpenAt2, (void**)&gOpenAt2, &gOpenAt2Addr);
    hookLibcSymbol(gHook, "__open64_2", (void*)fakeOpen2, (void**)&gOpen64_2, &gOpen64_2Addr);
    hookLibcSymbol(gHook, "__openat64_2", (void*)fakeOpenAt2, (void**)&gOpenAt64_2, &gOpenAt64_2Addr);
    hookLibcSymbol(gHook, "fopen", (void*)fakeFopen, (void**)&gFopen, &gFopenAddr);
    hookLibcSymbol(gHook, "close", (void*)fakeClose, (void**)&gClose, nullptr);

    hookLibcSymbol(gHook, "fstat", (void*)fakeFstat, (void**)&gFstat, &gFstatAddr);
    hookLibcSymbol(gHook, "fstat64", (void*)fakeFstat, (void**)&gFstat64, &gFstat64Addr);
    hookLibcSymbol(gHook, "mmap", (void*)fakeMmap, (void**)&gMmap, &gMmapAddr);
    hookLibcSymbol(gHook, "mmap64", (void*)fakeMmap, (void**)&gMmap64, &gMmap64Addr);

    hookLibcSymbol(gHook, "ioctl", (void*)fakeIoctl, (void**)&gIoctl, &gIoctlAddr);
    hookLibcSymbol(gHook, "syscall", (void*)fakeSyscall, (void**)&gSyscall, &gSyscallAddr);
    
    hookLibcSymbol(gHook, "system", (void*)fakeSystem, (void**)&gSystem, &gSystemAddr);
    hookLibcSymbol(gHook, "popen", (void*)fakePopen, (void**)&gPopen, &gPopenAddr);
    hookLibcSymbol(gHook, "execve", (void*)fakeExecve, (void**)&gExecve, &gExecveAddr);

    // ثبت هوک‌های توابع خروج جهت جلوگیری از متوقف شدن پردازه
    hookLibcSymbol(gHook, "exit", (void*)fakeExit, (void**)&gExit, &gExitAddr);
    hookLibcSymbol(gHook, "_exit", (void*)fake_Exit, (void**)&g_Exit, &g_ExitAddr);
    hookLibcSymbol(gHook, "_Exit", (void*)fake_Exit, (void**)&g_Exit, &g_ExitAddr);
    hookLibcSymbol(gHook, "abort", (void*)fakeAbort, (void**)&gAbort, &gAbortAddr);
    hookLibcSymbol(gHook, "kill", (void*)fakeKill, (void**)&gKill, &gKillAddr);
    hookLibcSymbol(gHook, "raise", (void*)fakeRaise, (void**)&gRaise, &gRaiseAddr);
}

static bool installHook() {
    if (gInstalled) return true;
    uintptr_t a = findGSpaceExport("MSHookFunction");
    if (!a) return false;
    gHook = (MSHookFunctionFn)a;
    gInstalled = 1;
    marker = getsmaps();
    libcScan();
    return true;
}

static void* worker(void*) {
    for (int i = 0; i < 300 && !gInstalled.load(); i++) {
        if (installHook()) break;
        usleep(100000);
    }
    return nullptr;
}

__attribute__((constructor))
static void onLibraryLoaded() {
    pthread_t t;
    if (pthread_create(&t, nullptr, worker, nullptr) == 0) pthread_detach(t);
}
