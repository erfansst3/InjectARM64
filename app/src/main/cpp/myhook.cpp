#include <jni.h>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <mutex>

#define TAG "InjectARM64"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

using MSHookFunctionFn = void (*)(void*, void*, void**);
using OpenFn = int (*)(const char*, int, ...);
using OpenAtFn = int (*)(int, const char*, int, ...);

static MSHookFunctionFn gMSHookFunction = nullptr;
static OpenFn gOriginalOpen = nullptr;
static OpenAtFn gOriginalOpenAt = nullptr;
static std::atomic<int> gInstalled{0};
static std::atomic<int> gHits{0};
static std::atomic<int> gGspaceFound{0};

static constexpr int kReaderPort = 39391;
static const char kTargetSuffix[] = "/kossher";

static std::mutex gBufferMutex;
static std::string gLastBuffer =
        "KOSSHER_BUFFER=NO_HIT\n"
        "STATUS=WAITING_FOR_/proc/<pid>/kossher\n";

struct GSpaceModule {
    uintptr_t base = 0;
    const ElfW(Phdr)* dynamicPhdr = nullptr;
};

static bool findGSpaceModule(GSpaceModule& out) {
    auto callback = [](dl_phdr_info* info, size_t, void* opaque) -> int {
        auto* module = static_cast<GSpaceModule*>(opaque);
        if (!info->dlpi_name || !std::strstr(info->dlpi_name, "libgspace_64.so")) {
            return 0;
        }
        module->base = static_cast<uintptr_t>(info->dlpi_addr);
        for (int i = 0; i < info->dlpi_phnum; ++i) {
            if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                module->dynamicPhdr = &info->dlpi_phdr[i];
                break;
            }
        }
        return 1;
    };
    dl_iterate_phdr(callback, &out);
    return out.base != 0 && out.dynamicPhdr != nullptr;
}

static uintptr_t dynPtr(uintptr_t base, ElfW(Addr) value) {
    return base + static_cast<uintptr_t>(value);
}

static size_t sysvHashSymbolCount(const ElfW(Word)* hash) {
    return hash ? static_cast<size_t>(hash[1]) : 0;
}

static size_t gnuHashSymbolCount(const uint32_t* gh) {
    if (!gh) return 0;
    const uint32_t nbuckets = gh[0];
    const uint32_t symoffset = gh[1];
    const uint32_t bloomSize = gh[2];
    if (nbuckets == 0) return symoffset;

    const uintptr_t wordSize = sizeof(ElfW(Addr));
    const uintptr_t* bloom = reinterpret_cast<const uintptr_t*>(gh + 4);
    const uint32_t* buckets =
            reinterpret_cast<const uint32_t*>(bloom) +
            bloomSize * (wordSize / sizeof(uint32_t));
    const uint32_t* chains = buckets + nbuckets;

    uint32_t maxSym = symoffset;
    for (uint32_t i = 0; i < nbuckets; ++i) {
        uint32_t idx = buckets[i];
        if (idx < symoffset) continue;
        while (idx >= symoffset) {
            if (idx > maxSym) maxSym = idx;
            const uint32_t h = chains[idx - symoffset];
            if (h & 1U) break;
            ++idx;
            if (idx > 10000000U) return 0;
        }
    }
    return static_cast<size_t>(maxSym) + 1;
}

static uintptr_t findGSpaceExport(const char* name) {
    GSpaceModule module;
    if (!findGSpaceModule(module)) return 0;
    gGspaceFound = 1;

    auto* dyn = reinterpret_cast<ElfW(Dyn)*>(
            module.base + module.dynamicPhdr->p_vaddr);

    ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    size_t strsz = 0;
    const ElfW(Word)* sysvHash = nullptr;
    const uint32_t* gnuHash = nullptr;

    for (; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
            case DT_SYMTAB:
                symtab = reinterpret_cast<ElfW(Sym)*>(
                        dynPtr(module.base, dyn->d_un.d_ptr));
                break;
            case DT_STRTAB:
                strtab = reinterpret_cast<const char*>(
                        dynPtr(module.base, dyn->d_un.d_ptr));
                break;
            case DT_STRSZ:
                strsz = static_cast<size_t>(dyn->d_un.d_val);
                break;
            case DT_HASH:
                sysvHash = reinterpret_cast<const ElfW(Word)*>(
                        dynPtr(module.base, dyn->d_un.d_ptr));
                break;
            case DT_GNU_HASH:
                gnuHash = reinterpret_cast<const uint32_t*>(
                        dynPtr(module.base, dyn->d_un.d_ptr));
                break;
        }
    }

    if (!symtab || !strtab || strsz == 0) return 0;

    void* handle = dlopen("libgspace_64.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        void* p = dlsym(handle, name);
        dlclose(handle);
        if (p) return reinterpret_cast<uintptr_t>(p);
    }

    size_t count = sysvHashSymbolCount(sysvHash);
    if (count == 0) count = gnuHashSymbolCount(gnuHash);
    if (count == 0) return 0;

    for (size_t i = 0; i < count; ++i) {
        const ElfW(Sym)& sym = symtab[i];
        if (sym.st_name == 0 || sym.st_name >= strsz) continue;
        if (sym.st_shndx == SHN_UNDEF) continue;
        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;

        const char* symbolName = strtab + sym.st_name;
        if (std::strcmp(symbolName, name) == 0) {
            return module.base + static_cast<uintptr_t>(sym.st_value);
        }
    }
    return 0;
}

static bool isKossherPath(const char* path) {
    if (!path || std::strncmp(path, "/proc/", 6) != 0) return false;

    const char* p = path + 6;
    if (*p < '0' || *p > '9') return false;

    while (*p >= '0' && *p <= '9') ++p;
    return std::strcmp(p, kTargetSuffix) == 0;
}

static std::string makeBuffer(const char* path) {
    char out[1024];
    const int n = std::snprintf(
            out, sizeof(out),
            "KOSSHER_BUFFER=ACTIVE\n"
            "HOOK=OPENAT\n"
            "PID=%d\n"
            "PATH=%s\n"
            "VALUE=InjectARM64_KOSSHER_TEST_OK\n"
            "IO=MEMFD_READ\n",
            getpid(), path);
    return n > 0 ? std::string(out, static_cast<size_t>(n)) : std::string();
}

static int makeFakeFd(const std::string& data) {
#ifdef SYS_memfd_create
    const int fd = static_cast<int>(
            syscall(SYS_memfd_create, "kossher", 0x0001 /* MFD_CLOEXEC */));
    if (fd < 0) return -1;

    size_t done = 0;
    while (done < data.size()) {
        const ssize_t n = syscall(
                SYS_write, fd, data.data() + done, data.size() - done);
        if (n <= 0) {
            syscall(SYS_close, fd);
            return -1;
        }
        done += static_cast<size_t>(n);
    }
    if (syscall(SYS_lseek, fd, 0, SEEK_SET) < 0) {
        syscall(SYS_close, fd);
        return -1;
    }
    return fd;
#else
    (void)data;
    return -1;
#endif
}

static int hookedOpenAt(int dirfd, const char* path, int flags, ...) {
    if (isKossherPath(path) && (flags & O_ACCMODE) != O_WRONLY) {
        const std::string data = makeBuffer(path);
        {
            std::lock_guard<std::mutex> lock(gBufferMutex);
            gLastBuffer = data;
        }
        ++gHits;

        const int fd = makeFakeFd(data);
        if (fd >= 0) {
            LOGI("KOSSHER OPENAT pid=%d path=%s fd=%d", getpid(), path, fd);
            return fd;
        }
    }

    if (!gOriginalOpenAt) {
        errno = ENOSYS;
        return -1;
    }

    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        const mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        return gOriginalOpenAt(dirfd, path, flags, mode);
    }
    return gOriginalOpenAt(dirfd, path, flags);
}

static int hookedOpen(const char* path, int flags, ...) {
    if (isKossherPath(path) && (flags & O_ACCMODE) != O_WRONLY) {
        const std::string data = makeBuffer(path);
        {
            std::lock_guard<std::mutex> lock(gBufferMutex);
            gLastBuffer = data;
        }
        ++gHits;

        const int fd = makeFakeFd(data);
        if (fd >= 0) {
            LOGI("KOSSHER OPEN pid=%d path=%s fd=%d", getpid(), path, fd);
            return fd;
        }
    }

    if (!gOriginalOpen) {
        errno = ENOSYS;
        return -1;
    }

    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        const mode_t mode = va_arg(ap, mode_t);
        va_end(ap);
        return gOriginalOpen(path, flags, mode);
    }
    return gOriginalOpen(path, flags);
}

static void* readerServer(void*) {
    const int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return nullptr;

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kReaderPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
        listen(s, 4) < 0) {
        close(s);
        return nullptr;
    }

    LOGI("KOSSHER READER port=%d pid=%d", kReaderPort, getpid());

    for (;;) {
        const int c = accept4(s, nullptr, nullptr, SOCK_CLOEXEC);
        if (c < 0) continue;

        std::string data;
        {
            std::lock_guard<std::mutex> lock(gBufferMutex);
            data = gLastBuffer;
        }

        uint32_t len = htonl(static_cast<uint32_t>(data.size()));
        (void)send(c, &len, sizeof(len), MSG_NOSIGNAL);

        size_t sent = 0;
        while (sent < data.size()) {
            const ssize_t n = send(
                    c, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
            if (n <= 0) break;
            sent += static_cast<size_t>(n);
        }
        close(c);
    }
    return nullptr;
}

static void startReaderServer() {
    pthread_t t;
    if (pthread_create(&t, nullptr, readerServer, nullptr) == 0) {
        pthread_detach(t);
    }
}

static bool installHook() {
    if (gInstalled.load()) return true;

    const uintptr_t hookAddress = findGSpaceExport("MSHookFunction");
    if (!hookAddress) return false;

    auto hook = reinterpret_cast<MSHookFunctionFn>(hookAddress);
    bool any = false;

    void* openAt = dlsym(RTLD_DEFAULT, "openat");
    if (openAt) {
        void* original = nullptr;
        hook(openAt, reinterpret_cast<void*>(hookedOpenAt), &original);
        if (original) {
            gOriginalOpenAt = reinterpret_cast<OpenAtFn>(original);
            any = true;
        }
    }

    void* openFn = dlsym(RTLD_DEFAULT, "open");
    if (openFn) {
        void* original = nullptr;
        hook(openFn, reinterpret_cast<void*>(hookedOpen), &original);
        if (original) {
            gOriginalOpen = reinterpret_cast<OpenFn>(original);
            any = true;
        }
    }

    if (!any) return false;

    gMSHookFunction = hook;
    gInstalled = 1;
    LOGI("KOSSHER HOOK INSTALLED pid=%d MSHookFunction=%p openat=%p open=%p",
         getpid(), reinterpret_cast<void*>(hookAddress), openAt, openFn);
    return true;
}

static void* worker(void*) {
    LOGI("libmyhook loaded pid=%d", getpid());

    for (int i = 0; i < 300 && !gInstalled.load(); ++i) {
        if (installHook()) break;
        usleep(100000);
    }

    if (!gInstalled.load()) {
        LOGW("KOSSHER hook timed out; GSpace=%s",
             gGspaceFound.load() ? "FOUND" : "NOT_FOUND");
    }
    return nullptr;
}

static void startWorker() {
    static std::atomic<int> started{0};
    if (started.exchange(1)) return;

    pthread_t t;
    if (pthread_create(&t, nullptr, worker, nullptr) == 0) {
        pthread_detach(t);
    }
}

__attribute__((constructor))
static void onLibraryLoaded() {
    startWorker();
    startReaderServer();
}

static std::string statusString() {
    std::string out;
    out += "PID=" + std::to_string(getpid()) + "\n";
    out += "GSPACE=" + std::string(gGspaceFound.load() ? "FOUND" : "NOT_FOUND") + "\n";
    out += "MSHookFunction=" +
           std::string(gMSHookFunction ? "FOUND" : "NOT_FOUND") + "\n";
    out += "HOOK=" +
           std::string(gInstalled.load() ? "INSTALLED" : "NOT_INSTALLED") + "\n";
    out += "KOSSHER_HITS=" + std::to_string(gHits.load()) + "\n";
    out += "READER_PORT=" + std::to_string(kReaderPort) + "\n";
    return out;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst_procmapdetector_MainActivity_nativeMyHookTest(
        JNIEnv* env, jobject) {
    installHook();
    const std::string s = statusString();
    return env->NewStringUTF(s.c_str());
}
