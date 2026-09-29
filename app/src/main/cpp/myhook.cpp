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
#include <pthread.h>
#include <errno.h>
#include <utility>

// هدرهای لازم برای Seccomp و SIGSYS
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <ucontext.h>

#define TAG "InjectARM64"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG,__VA_ARGS__)

using MSHookFunctionFn=void(*)(void*,void*,void**);
using OpenFn=int(*)(const char*,int,...);
using OpenAtFn=int(*)(int,const char*,int,...);
using PreadFn=ssize_t(*)(int,void*,size_t,off_t);
using Open2Fn=int(*)(const char*,int);
using OpenAt2Fn=int(*)(int,const char*,int);
using MmapFn=void*(*)(void*,size_t,int,int,int,off_t);
using FopenFn=FILE*(*)(const char*,const char*);
using ReadFn=ssize_t(*)(int,void*,size_t);
using FreadFn=size_t(*)(void*,size_t,size_t,FILE*);
using IoctlCallFn=int(*)(int,unsigned long,void*);
using SyscallCallFn=long(*)(long,long,long,long,long,long,long);

static MSHookFunctionFn gHook = nullptr;

// اشاره‌گر به توابع اصلی
static OpenFn gOpen = nullptr;
static OpenAtFn gOpenAt = nullptr;
static Open2Fn gOpen2 = nullptr;
static OpenAt2Fn gOpenAt2 = nullptr;
static Open2Fn gOpen64_2 = nullptr;
static OpenAt2Fn gOpenAt64_2 = nullptr;
static PreadFn gPread = nullptr;
static PreadFn gPread64 = nullptr;
static MmapFn gMmap = nullptr;
static MmapFn gMmap64 = nullptr;
static FopenFn gFopen = nullptr;
static ReadFn gRead = nullptr;
static FreadFn gFread = nullptr;

static IoctlCallFn gIoctlImport = nullptr;
static SyscallCallFn gSyscallImport = nullptr;

static std::atomic<int> gInstalled{0},gGspaceFound{0};
static std::atomic<int> hOpenAt{0},hOpen{0},hFopen{0},hPread{0},hMmap{0},hIoctl{0},hSyscall{0},hRead{0},hFread{0};
static std::atomic<int> hSyscallOpenat{0}, hDirectSvcOpenat{0};

// پرچم‌های محلی نخ جهت جلوگیری از Reentrancy
static thread_local bool g_inside_hook = false;
static thread_local bool g_inside_ioctl = false;

static void* gLibc = nullptr;

// محدوده حافظه کتابخانه‌های مجاز برای Seccomp
struct MemoryRange { uintptr_t start; uintptr_t end; };
static MemoryRange g_allowed_ranges[16];
static size_t g_allowed_range_count = 0;

struct HookRecord{void* addr;void* orig;void* repl;};
static HookRecord gHookRecords[32];
static int gHookRecordCount=0;

struct GSpaceModule{uintptr_t base=0;const ElfW(Phdr)* dynamicPhdr=nullptr;};

static bool findGSpaceModule(GSpaceModule& out){
    auto cb=[](dl_phdr_info* i,size_t,void* p)->int{
        auto* m=(GSpaceModule*)p;
        if(!i->dlpi_name||!strstr(i->dlpi_name,"libgspace_64.so"))return 0;
        m->base=(uintptr_t)i->dlpi_addr;
        for(int n=0;n<i->dlpi_phnum;n++)if(i->dlpi_phdr[n].p_type==PT_DYNAMIC){m->dynamicPhdr=&i->dlpi_phdr[n];break;}
        return 1;
    };
    dl_iterate_phdr(cb,&out);
    return out.base&&out.dynamicPhdr;
}

static uintptr_t dynPtr(uintptr_t b,ElfW(Addr) v){return b+(uintptr_t)v;}
static size_t sysvHashSymbolCount(const ElfW(Word)* h){return h?(size_t)h[1]:0;}

static size_t gnuHashSymbolCount(const uint32_t* h){
    if(!h)return 0;
    uint32_t nb=h[0],so=h[1],bs=h[2];
    if(!nb)return so;
    const uintptr_t* bloom=(const uintptr_t*)(h+4);
    const uint32_t* buckets=(const uint32_t*)bloom+bs*(sizeof(ElfW(Addr))/4);
    const uint32_t* chains=buckets+nb;
    uint32_t max=so;
    for(uint32_t i=0;i<nb;i++){
        uint32_t x=buckets[i];
        if(x<so)continue;
        while(x>=so){
            if(x>max)max=x;
            if(chains[x-so]&1)break;
            if(++x>10000000U)return 0;
        }
    }
    return (size_t)max+1;
}

static uintptr_t findGSpaceExport(const char* name){
    GSpaceModule m;
    if(!findGSpaceModule(m))return 0;
    gGspaceFound=1;
    auto* d=(ElfW(Dyn)*)(m.base+m.dynamicPhdr->p_vaddr);
    ElfW(Sym)* st=nullptr;const char* str=nullptr;size_t sz=0;const ElfW(Word)* sh=nullptr;const uint32_t* gh=nullptr;
    for(;d->d_tag!=DT_NULL;d++)switch(d->d_tag){
        case DT_SYMTAB:st=(ElfW(Sym)*)dynPtr(m.base,d->d_un.d_ptr);break;
        case DT_STRTAB:str=(const char*)dynPtr(m.base,d->d_un.d_ptr);break;
        case DT_STRSZ:sz=(size_t)d->d_un.d_val;break;
        case DT_HASH:sh=(const ElfW(Word)*)dynPtr(m.base,d->d_un.d_ptr);break;
        case DT_GNU_HASH:gh=(const uint32_t*)dynPtr(m.base,d->d_un.d_ptr);break;
    }
    if(!st||!str||!sz)return 0;
    void* h=dlopen("libgspace_64.so",RTLD_NOW|RTLD_NOLOAD);
    if(h){void* p=dlsym(h,name);dlclose(h);if(p)return(uintptr_t)p;}
    size_t n=sysvHashSymbolCount(sh);if(!n)n=gnuHashSymbolCount(gh);if(!n)return 0;
    for(size_t i=0;i<n;i++){
        auto&s=st[i];
        if(!s.st_name||s.st_name>=sz||s.st_shndx==SHN_UNDEF||ELF64_ST_TYPE(s.st_info)!=STT_FUNC)continue;
        if(!strcmp(str+s.st_name,name))return m.base+(uintptr_t)s.st_value;
    }
    return 0;
}

// بررسی سریع و امن آدرس مسیر
static bool isKossherPath(const char* p){
    if(!p || reinterpret_cast<uintptr_t>(p) < 0x1000) return false;
    if(strstr(p, "/maps") || strstr(p, "/status") || strstr(p, "/cmdline") || 
       strstr(p, "/stat") || strstr(p, "/mounts") || strstr(p, "/exe")) {
        return true;
    }
    if(strncmp(p,"/proc/",6) == 0){
        p+=6;
        if(*p<'0'||*p>'9')return false;
        while(*p>='0'&&*p<='9')p++;
        return !strcmp(p,"/kossher");
    }
    return false;
}

static std::string marker(){
    char b[1200];
    int n=snprintf(b,sizeof(b),
        "KOSSHER_BUFFER=ACTIVE\nPID=%d\n"
        "OPENAT_HIT=%d\nOPEN_HIT=%d\nFOPEN_HIT=%d\n"
        "PREAD_HIT=%d\nMMAP_HIT=%d\nIOCTL_HIT=%d\nSYSCALL_HIT=%d\n"
        "READ_HIT=%d\nFREAD_HIT=%d\nDIRECT_SVC_HIT=%d\n",
        getpid(),hOpenAt.load(),hOpen.load(),hFopen.load(),
        hPread.load(),hMmap.load(),hIoctl.load(),hSyscall.load(),hRead.load(),hFread.load(),
        hDirectSvcOpenat.load());
    return n>0?std::string(b,(size_t)n):std::string();
}

static int makeFakeFd(const std::string& d){
#ifdef SYS_memfd_create
    int fd=(int)syscall(SYS_memfd_create,"kossher",1);
    if(fd<0)return -1;
    size_t n=0;
    while(n<d.size()){
        ssize_t w=syscall(SYS_write,fd,d.data()+n,d.size()-n);
        if(w<=0){syscall(SYS_close,fd);return -1;}
        n+=(size_t)w;
    }
    syscall(SYS_lseek,fd,0,SEEK_SET);
    return fd;
#else
    return -1;
#endif
}

// ---------------------------------------------------------------------------
// توابع پروکسی C Hooks (اینلاین و GOT)
// ---------------------------------------------------------------------------

static int fakeOpenAt(int d,const char* p,int f,...){
    if(g_inside_hook) {
        if(!gOpenAt){errno=ENOSYS;return -1;}
        va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
        return gOpenAt(d,p,f,m);
    }
    g_inside_hook = true;

    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        hOpenAt++;
        int fd=makeFakeFd(marker());
        if(fd>=0){
            LOGI("HOOK openat %s pid=%d fd=%d",p,getpid(),fd);
            g_inside_hook = false;
            return fd;
        }
    }
    
    va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
    int res = gOpenAt ? gOpenAt(d,p,f,m) : openat(d,p,f,m);
    g_inside_hook = false;
    return res;
}

static int fakeOpen(const char* p,int f,...){
    if(g_inside_hook) {
        if(!gOpen){errno=ENOSYS;return -1;}
        va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
        return (f&O_CREAT)?gOpen(p,f,m):gOpen(p,f);
    }
    g_inside_hook = true;

    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        hOpen++;
        int fd=makeFakeFd(marker());
        if(fd>=0){
            LOGI("HOOK open %s pid=%d fd=%d",p,getpid(),fd);
            g_inside_hook = false;
            return fd;
        }
    }

    va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
    int res = gOpen ? ((f&O_CREAT)?gOpen(p,f,m):gOpen(p,f)) : open(p,f,m);
    g_inside_hook = false;
    return res;
}

static FILE* fakeFopen(const char* p,const char* m){
    if(g_inside_hook) return gFopen ? gFopen(p,m) : fopen(p,m);
    g_inside_hook = true;

    if(isKossherPath(p)){
        hFopen++;
        int fd=makeFakeFd(marker());
        if(fd>=0){
            LOGI("HOOK fopen %s pid=%d fd=%d",p,getpid(),fd);
            g_inside_hook = false;
            return fdopen(fd,m&&*m?m:"r");
        }
    }

    FILE* res = gFopen ? gFopen(p,m) : fopen(p,m);
    g_inside_hook = false;
    return res;
}

static ssize_t fakeRead(int fd,void* b,size_t n){
    hRead++;
    return gRead?gRead(fd,b,n):read(fd,b,n);
}

static ssize_t fakePread(int fd,void* b,size_t n,off_t o){
    hPread++;
    return gPread?gPread(fd,b,n,o):pread(fd,b,n,o);
}

static void* fakeMmap(void* a,size_t n,int p,int f,int fd,off_t o){
    hMmap++;
    return gMmap?gMmap(a,n,p,f,fd,o):(gMmap64?gMmap64(a,n,p,f,fd,o):mmap(a,n,p,f,fd,o));
}

static int fakeIoctlImport(int fd,unsigned long request,void* arg){
    if(g_inside_ioctl || fd < 0){
        return gIoctlImport ? gIoctlImport(fd,request,arg) : ioctl(fd,request,arg);
    }
    g_inside_ioctl = true;
    hIoctl++;
    int res = gIoctlImport ? gIoctlImport(fd,request,arg) : ioctl(fd,request,arg);
    g_inside_ioctl = false;
    return res;
}

static long fakeSyscallImport(long number,long a1,long a2,long a3,long a4,long a5,long a6){
    if(g_inside_hook){
        return gSyscallImport ? gSyscallImport(number,a1,a2,a3,a4,a5,a6) : syscall(number,a1,a2,a3,a4,a5,a6);
    }
    g_inside_hook = true;
    hSyscall++;

#ifdef SYS_openat
    if(number==SYS_openat){
        const char* path=(const char*)a2;
        const int flags=(int)a3;
        if(isKossherPath(path) && (flags&O_ACCMODE)!=O_WRONLY){
            hSyscallOpenat++;
            int fd=makeFakeFd(marker());
            if(fd>=0){
                LOGI("HOOK syscall(SYS_openat) %s pid=%d fd=%d",path,getpid(),fd);
                g_inside_hook = false;
                return fd;
            }
        }
    }
#endif

    long ret = gSyscallImport ? gSyscallImport(number,a1,a2,a3,a4,a5,a6) : syscall(number,a1,a2,a3,a4,a5,a6);
    g_inside_hook = false;
    return ret;
}

// ---------------------------------------------------------------------------
// Seccomp + SIGSYS با چک کردن محدوده حافظه مجاز
// ---------------------------------------------------------------------------

static bool is_in_allowed_range(uintptr_t pc) {
    for (size_t i = 0; i < g_allowed_range_count; i++) {
        if (pc >= g_allowed_ranges[i].start && pc < g_allowed_ranges[i].end) {
            return true;
        }
    }
    return false;
}

static void init_allowed_ranges() {
    g_allowed_range_count = 0;
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void*) -> int {
        if (info->dlpi_name && (strstr(info->dlpi_name, "libc.so") || strstr(info->dlpi_name, "libmyhook.so") || strstr(info->dlpi_name, "libgspace"))) {
            for (int i = 0; i < info->dlpi_phnum; i++) {
                if (info->dlpi_phdr[i].p_type == PT_LOAD) {
                    if (g_allowed_range_count < 16) {
                        g_allowed_ranges[g_allowed_range_count++] = {
                            info->dlpi_addr + info->dlpi_phdr[i].p_vaddr,
                            info->dlpi_addr + info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz
                        };
                    }
                }
            }
        }
        return 0;
    }, nullptr);
}

static void sigsys_handler(int, siginfo_t*, void* void_context) {
    ucontext_t* ctx = static_cast<ucontext_t*>(void_context);
    uint64_t syscall_num = ctx->uc_mcontext.regs[8]; // x8 در ARM64
    uintptr_t pc = ctx->uc_mcontext.pc;

    if (syscall_num == __NR_openat) {
        int dirfd = static_cast<int>(ctx->uc_mcontext.regs[0]);
        const char* path = reinterpret_cast<const char*>(ctx->uc_mcontext.regs[1]);
        int flags = static_cast<int>(ctx->uc_mcontext.regs[2]);
        mode_t mode = static_cast<mode_t>(ctx->uc_mcontext.regs[3]);

        // اگر فراخوانی از داخل libc.so یا کتابخانه هوک صادر شده باشد، اجرای عادی
        if (is_in_allowed_range(pc)) {
            long res = syscall(__NR_openat, dirfd, path, flags, mode);
            ctx->uc_mcontext.regs[0] = static_cast<uint64_t>(res);
            ctx->uc_mcontext.pc += 4;
            return;
        }

        // اگر فراخوانی مستقیماً از اسمبلی (svc #0) درون شناساگر صادر شده باشد
        if (isKossherPath(path)) {
            hDirectSvcOpenat++;
            int fake_fd = makeFakeFd(marker());
            if (fake_fd >= 0) {
                LOGI("HOOK Direct SVC #0 (__NR_openat) %s pid=%d fd=%d", path, getpid(), fake_fd);
                ctx->uc_mcontext.regs[0] = static_cast<uint64_t>(fake_fd);
                ctx->uc_mcontext.pc += 4;
                return;
            }
        }

        long real_fd = syscall(__NR_openat, dirfd, path, flags, mode);
        ctx->uc_mcontext.regs[0] = static_cast<uint64_t>(real_fd);
        ctx->uc_mcontext.pc += 4;
        return;
    }

    ctx->uc_mcontext.pc += 4;
}

static bool setup_seccomp_svc_hook() {
    init_allowed_ranges();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSYS, &sa, nullptr) != 0) return false;

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) return false;

    LOGI("SECCOMP_SVC_HOOK_INSTALLED");
    return true;
}

// ---------------------------------------------------------------------------
// اسکن و نصب هوک‌ها
// ---------------------------------------------------------------------------

static bool hookLibcSymbol(MSHookFunctionFn h,const char* n,void* repl,void** orig,void** addrStore){
    if(!gLibc||!n||!orig)return false;
    void* p=dlsym(gLibc,n);
    if(!p) return false;
    if(addrStore)*addrStore=p;

    for(int i=0;i<gHookRecordCount;i++){
        if(gHookRecords[i].addr==p){
            *orig=gHookRecords[i].orig;
            return *orig!=nullptr;
        }
    }

    void* saved=nullptr;
    h(p,repl,&saved);
    if(!saved)return false;
    if(gHookRecordCount<(int)(sizeof(gHookRecords)/sizeof(gHookRecords[0]))){
        gHookRecords[gHookRecordCount++]={p,saved,repl};
    }
    *orig=saved;
    return true;
}

static void libcScan(){
    gLibc=dlopen("libc.so",RTLD_NOW);
    if(!gLibc) return;

    // نصب هوک‌های اینلاین روی libc.so
    hookLibcSymbol(gHook,"open",(void*)fakeOpen,(void**)&gOpen,nullptr);
    hookLibcSymbol(gHook,"openat",(void*)fakeOpenAt,(void**)&gOpenAt,nullptr);
    hookLibcSymbol(gHook,"fopen",(void*)fakeFopen,(void**)&gFopen,nullptr);
    hookLibcSymbol(gHook,"read",(void*)fakeRead,(void**)&gRead,nullptr);
    hookLibcSymbol(gHook,"pread",(void*)fakePread,(void**)&gPread,nullptr);
    hookLibcSymbol(gHook,"mmap",(void*)fakeMmap,(void**)&gMmap,nullptr);

    void* libcIoctl=dlsym(gLibc,"ioctl");
    void* libcSyscall=dlsym(gLibc,"syscall");
    if(libcIoctl) gIoctlImport=(IoctlCallFn)libcIoctl;
    if(libcSyscall) gSyscallImport=(SyscallCallFn)libcSyscall;
}

static bool installHook(){
    if(gInstalled)return true;
    uintptr_t a=findGSpaceExport("MSHookFunction");
    if(!a)return false;
    gHook=(MSHookFunctionFn)a;
    gInstalled=1;

    libcScan();
    setup_seccomp_svc_hook();

    LOGI("ALL_HOOKS_AND_SECCOMP_READY");
    return true;
}

static void* worker(void*){
    for(int i=0;i<300&&!gInstalled.load();i++){
        if(installHook())break;
        usleep(100000);
    }
    return nullptr;
}

__attribute__((constructor))
static void onLibraryLoaded(){
    pthread_t t;
    if(pthread_create(&t,nullptr,worker,nullptr)==0)pthread_detach(t);
}
