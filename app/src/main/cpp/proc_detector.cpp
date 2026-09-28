#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <mutex>
#include <atomic>
#include <link.h>
#include <elf.h>
#include <cstdint>

#define TAG "GspaceHookTest"

using MSHookFunctionFn = void(*)(void*, void*, void**);
using PutsFn = int(*)(const char*);

static MSHookFunctionFn gMSHookFunction = nullptr;
static PutsFn gLibcPuts = nullptr;
static PutsFn gOriginalPuts = nullptr;

static std::mutex gMutex;
static std::string gLog;
static std::atomic<int> gHookHits{0};
static std::atomic<int> gTestRuns{0};

static bool gInstalled = false;
static bool gApiFound = false;
static std::string gGspacePath;
static uintptr_t gGspaceBase = 0;
static uintptr_t gPutsAddr = 0;

static void logLine(const std::string& s) {
    std::lock_guard<std::mutex> lock(gMutex);
    gLog += s + "\n";
    __android_log_print(ANDROID_LOG_INFO, TAG, "%s", s.c_str());
}

static std::string hexAddr(uintptr_t value) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(value));
    return std::string(buf);
}

static int hookedPuts(const char* text) {
    ++gHookHits;

    // Keep the hook side-effect free: no C++ logging or other libc work here.
    const int result = gOriginalPuts ? gOriginalPuts(text) : -1;
    return result;
}

static bool resolveGspaceSymbol(const char* target, uintptr_t& outAddr) {
    struct Context {
        const char* target;
        uintptr_t symbolAddr;
        bool found;
        std::string* path;
        uintptr_t* base;
    };

    Context ctx{target, 0, false, &gGspacePath, &gGspaceBase};

    auto callback = [](struct dl_phdr_info* info, size_t, void* opaque) -> int {
        auto* c = reinterpret_cast<Context*>(opaque);

        if (!info->dlpi_name ||
            !std::strstr(info->dlpi_name, "libgspace_64.so")) {
            return 0;
        }

        if (c->path->empty()) {
            *c->path = info->dlpi_name;
            *c->base = static_cast<uintptr_t>(info->dlpi_addr);
        }

        const ElfW(Phdr)* dynamicPhdr = nullptr;
        for (int i = 0; i < info->dlpi_phnum; ++i) {
            if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                dynamicPhdr = &info->dlpi_phdr[i];
                break;
            }
        }
        if (!dynamicPhdr) {
            return 0;
        }

        auto* dynamic = reinterpret_cast<ElfW(Dyn)*>(
            info->dlpi_addr + dynamicPhdr->p_vaddr);

        ElfW(Sym)* symtab = nullptr;
        const char* strtab = nullptr;
        size_t strsz = 0;
        ElfW(Word)* hash = nullptr;

        for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
            switch (d->d_tag) {
                case DT_SYMTAB:
                    symtab = reinterpret_cast<ElfW(Sym)*>(
                        info->dlpi_addr + d->d_un.d_ptr);
                    break;
                case DT_STRTAB:
                    strtab = reinterpret_cast<const char*>(
                        info->dlpi_addr + d->d_un.d_ptr);
                    break;
                case DT_STRSZ:
                    strsz = static_cast<size_t>(d->d_un.d_val);
                    break;
                case DT_HASH:
                    hash = reinterpret_cast<ElfW(Word)*>(
                        info->dlpi_addr + d->d_un.d_ptr);
                    break;
                default:
                    break;
            }
        }

        if (!symtab || !strtab || !strsz || !hash) {
            return 0;
        }

        const size_t symbolCount = static_cast<size_t>(hash[1]);
        for (size_t i = 0; i < symbolCount; ++i) {
            const ElfW(Sym)& symbol = symtab[i];

            if (!symbol.st_name ||
                symbol.st_name >= strsz ||
                symbol.st_shndx == SHN_UNDEF) {
                continue;
            }

            const char* name = strtab + symbol.st_name;
            if (std::strcmp(name, c->target) != 0) {
                continue;
            }

            if (ELF64_ST_TYPE(symbol.st_info) != STT_FUNC) {
                continue;
            }

            c->symbolAddr = static_cast<uintptr_t>(
                info->dlpi_addr + symbol.st_value);
            c->found = true;
            return 1;
        }

        return 0;
    };

    dl_iterate_phdr(callback, &ctx);

    if (!ctx.found) {
        return false;
    }

    outAddr = ctx.symbolAddr;
    return true;
}

static bool resolveHookApi() {
    uintptr_t addr = 0;
    if (!resolveGspaceSymbol("MSHookFunction", addr)) {
        logLine("MSHookFunction: NOT_FOUND");
        return false;
    }

    gMSHookFunction = reinterpret_cast<MSHookFunctionFn>(addr);
    gApiFound = true;

    logLine("GSPACE: loaded");
    logLine("GSPACE base=" + hexAddr(gGspaceBase));
    logLine("MSHookFunction=" + hexAddr(addr));
    logLine("HOOK API: READY");
    return true;
}

static bool resolveLibcPuts() {
    void* addr = dlsym(RTLD_DEFAULT, "puts");
    if (!addr) {
        logLine("libc puts: NOT_FOUND");
        const char* err = dlerror();
        if (err) {
            logLine(std::string("dlsym error=") + err);
        }
        return false;
    }

    gLibcPuts = reinterpret_cast<PutsFn>(addr);
    gPutsAddr = reinterpret_cast<uintptr_t>(addr);

    Dl_info info{};
    if (dladdr(addr, &info) && info.dli_fname) {
        logLine("libc puts module=" + std::string(info.dli_fname));
    }
    logLine("libc puts=" + hexAddr(gPutsAddr));
    return true;
}

static std::string snapshot();

static bool installHook() {
    if (gInstalled) {
        return true;
    }

    if (!resolveHookApi()) {
        return false;
    }

    if (!resolveLibcPuts()) {
        return false;
    }

    void* original = nullptr;
    gMSHookFunction(
        reinterpret_cast<void*>(gLibcPuts),
        reinterpret_cast<void*>(&hookedPuts),
        &original);

    gOriginalPuts = reinterpret_cast<PutsFn>(original);
    if (!gOriginalPuts) {
        logLine("HOOK: libc puts trampoline=NO");
        return false;
    }

    gInstalled = true;
    logLine("HOOK: libc puts=INSTALLED");
    return true;
}

static std::string runHookTest() {
    if (!resolveLibcPuts()) {
        return snapshot();
    }

    gHookHits = 0;
    const int beforeResult = gLibcPuts("LIBC BEFORE HOOK");

    if (!installHook()) {
        return snapshot();
    }

    gHookHits = 0;
    const int afterResult = gLibcPuts("LIBC AFTER HOOK");
    ++gTestRuns;

    const int hits = gHookHits.load();

    logLine("BEFORE result=" + std::to_string(beforeResult));
    logLine("AFTER result=" + std::to_string(afterResult));
    logLine("CALLBACK hits=" + std::to_string(hits));

    if (afterResult >= 0 && hits > 0) {
        logLine("RESULT: PASS");
    } else {
        logLine("RESULT: FAILED");
    }

    return snapshot();
}

static std::string snapshot() {
    std::lock_guard<std::mutex> lock(gMutex);

    std::string s = gLog;
    s += "STATUS\n";
    s += "gspace=" + std::string(gGspacePath.empty() ? "NOT_FOUND" : "YES") + "\n";
    s += "MSHookFunction=" + std::string(gApiFound ? "YES" : "NO") + "\n";
    s += "libc_puts=" + std::string(gLibcPuts ? "YES" : "NO") + "\n";
    s += "local_libc_hook=" + std::string(gInstalled ? "YES" : "NO") + "\n";
    s += "hook_hits=" + std::to_string(gHookHits.load()) + "\n";
    s += "test_runs=" + std::to_string(gTestRuns.load()) + "\n";
    return s;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst_procmapdetector_MainActivity_runHookTest(
    JNIEnv* env, jobject) {
    const std::string result = runHookTest();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst_procmapdetector_MainActivity_getLog(
    JNIEnv* env, jobject) {
    const std::string result = snapshot();
    return env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst_procmapdetector_MainActivity_clearLog(
    JNIEnv* env, jobject) {
    {
        std::lock_guard<std::mutex> lock(gMutex);
        gLog.clear();
    }
    gHookHits = 0;
    gTestRuns = 0;
    const std::string result = snapshot();
    return env->NewStringUTF(result.c_str());
}
