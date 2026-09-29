#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <errno.h>

#define TAG "InjectARM64"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

using MSHookFunctionFn = void (*)(void*, void*, void**);
using ReadFn = ssize_t (*)(int, void*, size_t);

static MSHookFunctionFn gMSHookFunction = nullptr;
static ReadFn gOriginalRead = nullptr;
static std::atomic<int> gInstalled{0};
static std::atomic<int> gHits{0};
static std::atomic<int> gGspaceFound{0};

static const char kMarker[] = "\nInjectARM64_HOOK=ACTIVE\n";

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
    // On Android/PIE shared objects, DT_* pointers are normally relative to
    // the load bias. Some vendor loaders expose already-relocated pointers;
    // prefer the normal load-bias form and fall back when it is implausible.
    return base + static_cast<uintptr_t>(value);
}

static size_t sysvHashSymbolCount(const ElfW(Word)* hash) {
    return hash ? static_cast<size_t>(hash[1]) : 0;
}

static size_t gnuHashSymbolCount(const uint32_t* gh, const ElfW(Sym)* symtab) {
    if (!gh || !symtab) return 0;

    const uint32_t nbuckets = gh[0];
    const uint32_t symoffset = gh[1];
    const uint32_t bloomSize = gh[2];
    if (nbuckets == 0) return symoffset;

    const uintptr_t wordSize = sizeof(ElfW(Addr));
    const uintptr_t* bloom =
        reinterpret_cast<const uintptr_t*>(gh + 4);
    const uint32_t* buckets =
        reinterpret_cast<const uint32_t*>(bloom) + bloomSize * (wordSize / sizeof(uint32_t));
    const uint32_t* chains = buckets + nbuckets;

    uint32_t maxSym = symoffset;
    for (uint32_t i = 0; i < nbuckets; ++i) {
        uint32_t b = buckets[i];
        if (b < symoffset) continue;
        uint32_t idx = b;
        while (true) {
            if (idx > maxSym) maxSym = idx;
            uint32_t h = chains[idx - symoffset];
            if (h & 1U) break;
            ++idx;
            if (idx > 10000000U) return 0;
        }
    }
    (void)symtab;
    return static_cast<size_t>(maxSym) + 1;
}

static uintptr_t findGSpaceExport(const char* name) {
    GSpaceModule module;
    if (!findGSpaceModule(module)) {
        return 0;
    }
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

    if (!symtab || !strtab || strsz == 0) {
        return 0;
    }

    // First use the loader's symbol lookup, which is the most reliable
    // option when the symbol is present in the dynamic symbol table.
    void* handle = dlopen("libgspace_64.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle) {
        void* p = dlsym(handle, name);
        dlclose(handle);
        if (p) {
            return reinterpret_cast<uintptr_t>(p);
        }
    }

    size_t count = sysvHashSymbolCount(sysvHash);
    if (count == 0 && gnuHash) {
        count = gnuHashSymbolCount(gnuHash, symtab);
    }
    if (count == 0) {
        return 0;
    }

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

static bool isProcSelfStatusFd(int fd) {
    char path[64];
    const int n = std::snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (n <= 0 || n >= static_cast<int>(sizeof(path))) return false;

    char target[256];
    const ssize_t r = syscall(SYS_readlinkat, AT_FDCWD, path,
                              target, sizeof(target) - 1);
    if (r <= 0) return false;
    target[r] = '\0';

    return std::strcmp(target, "/proc/self/status") == 0;
}

static ssize_t hookedRead(int fd, void* buf, size_t count) {
    const ssize_t result =
        gOriginalRead ? gOriginalRead(fd, buf, count)
                      : static_cast<ssize_t>(syscall(SYS_read, fd, buf, count));

    if (result > 0 && buf && isProcSelfStatusFd(fd)) {
        ++gHits;
        const size_t markerLen = sizeof(kMarker) - 1;
        if (static_cast<size_t>(result) + markerLen < count) {
            std::memcpy(static_cast<char*>(buf) + result, kMarker, markerLen);
            return result + static_cast<ssize_t>(markerLen);
        }
    }

    return result;
}

static bool installHook() {
    if (gInstalled.load()) return true;

    const uintptr_t hookAddress = findGSpaceExport("MSHookFunction");
    if (!hookAddress) {
        return false;
    }

    auto hook = reinterpret_cast<MSHookFunctionFn>(hookAddress);

    void* readAddress = dlsym(RTLD_DEFAULT, "read");
    if (!readAddress) {
        LOGE("libc read not found: %s", dlerror());
        return false;
    }

    void* original = nullptr;
    hook(readAddress, reinterpret_cast<void*>(hookedRead), &original);
    if (!original) {
        LOGE("MSHookFunction returned no original read pointer");
        return false;
    }

    gMSHookFunction = hook;
    gOriginalRead = reinterpret_cast<ReadFn>(original);
    gInstalled = 1;

    LOGI("HOOK INSTALLED pid=%d MSHookFunction=%p read=%p",
         getpid(), reinterpret_cast<void*>(hookAddress), readAddress);
    return true;
}

static void* worker(void*) {
    LOGI("libmyhook loaded pid=%d", getpid());

    // GSpace may be loaded after the guest runtime starts.
    for (int i = 0; i < 300 && !gInstalled.load(); ++i) {
        if (installHook()) break;
        usleep(100000);
    }

    if (!gInstalled.load()) {
        LOGW("hook install timed out; GSpace=%s",
             gGspaceFound.load() ? "FOUND" : "NOT_FOUND");
    }
    return nullptr;
}

static void startWorker() {
    static std::atomic<int> started{0};
    if (started.exchange(1)) return;

    pthread_t thread;
    if (pthread_create(&thread, nullptr, worker, nullptr) == 0) {
        pthread_detach(thread);
    } else {
        LOGE("pthread_create failed: %s", std::strerror(errno));
    }
}

__attribute__((constructor))
static void onLibraryLoaded() {
    startWorker();
}

static std::string statusString() {
    std::string out;
    out += "PID=" + std::to_string(getpid()) + "\n";
    out += "GSPACE=" + std::string(gGspaceFound.load() ? "FOUND" : "NOT_FOUND") + "\n";
    out += "MSHookFunction=" +
           std::string(gMSHookFunction ? "FOUND" : "NOT_FOUND") + "\n";
    out += "HOOK=" +
           std::string(gInstalled.load() ? "INSTALLED" : "NOT_INSTALLED") + "\n";
    out += "READ_HITS=" + std::to_string(gHits.load()) + "\n";
    return out;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst_procmapdetector_MainActivity_nativeMyHookTest(
        JNIEnv* env, jobject) {
    installHook();

    if (gOriginalRead) {
        char buffer[1024] = {};
        int fd = syscall(SYS_openat, AT_FDCWD,
                         "/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            const ssize_t n = gOriginalRead(fd, buffer, sizeof(buffer) - 1);
            syscall(SYS_close, fd);
            if (n > 0) {
                buffer[n] = '\0';
                if (std::strstr(buffer, "InjectARM64_HOOK=ACTIVE")) {
                    ++gHits;
                }
            }
        }
    }

    const std::string s = statusString();
    return env->NewStringUTF(s.c_str());
}
