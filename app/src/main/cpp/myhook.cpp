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

// هدرهای لازم برای مدیریت Seccomp و سیگنال SIGSYS
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
using PreadChkFn=ssize_t(*)(int,void*,size_t,off_t,size_t);
using MmapFn=void*(*)(void*,size_t,int,int,int,off_t);
using FopenFn=FILE*(*)(const char*,const char*);
using ReadFn=ssize_t(*)(int,void*,size_t);
using FreadFn=size_t(*)(void*,size_t,size_t,FILE*);
using IoctlCallFn=int(*)(int,unsigned long,void*);
using SyscallCallFn=long(*)(long,long,long,long,long,long,long);

static MSHookFunctionFn gHook = nullptr;
static OpenFn gOpen = nullptr;
static OpenAtFn gOpenAt = nullptr;
static Open2Fn gOpen2 = nullptr;
static OpenAt2Fn gOpenAt2 = nullptr;
static Open2Fn gOpen64_2 = nullptr;
static OpenAt2Fn gOpenAt64_2 = nullptr;
static PreadFn gPread = nullptr;
static PreadFn gPread64 = nullptr;
static PreadChkFn gPread64Chk = nullptr;
static MmapFn gMmap = nullptr;
static MmapFn gMmap64 = nullptr;
static FopenFn gFopen = nullptr;
static ReadFn gRead = nullptr;
static FreadFn gFread = nullptr;

static IoctlCallFn gIoctlImport = nullptr;
static SyscallCallFn gSyscallImport = nullptr;

static std::atomic<int> gIoctlImportHooked{0},gSyscallImportHooked{0};
static std::atomic<int> gInstalled{0},gGspaceFound{0};
static std::atomic<int> hOpenAt{0},hOpen{0},hFopen{0},hPread{0},hMmap{0},hIoctl{0},hSyscall{0},hRead{0},hFread{0};
static std::atomic<int> hSyscallOpenat{0}, hDirectSvcOpenat{0};

// جلوگیری از حلقه‌های بازگشتی درون‌نخی
static thread_local bool g_inside_hook = false;
static thread_local bool g_inside_ioctl = false;

// محدوده حافظه libc.so
static uintptr_t g_libc_start = 0;
static uintptr_t g_libc_end = 0;

static void* gLibc = nullptr;
static void* gOpenAddr = nullptr;
static void* gOpenAtAddr = nullptr;

struct HookRecord{void* addr;void* orig;void* repl;};
static HookRecord gHookRecords[32];static int gHookRecordCount=0;

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

// بررسی سلامت اشاره‌گر رشته در حافظه
static bool is_valid_string_ptr(const void* ptr) {
    if (!ptr) return false;
    int pfd[2];
    if (pipe(pfd) < 0) return true;
    ssize_t n = write(pfd[1], ptr, 1);
    close(pfd[0]);
    close(pfd[1]);
    return n == 1;
}

static bool isKossherPath(const char* p){
    if(!is_valid_string_ptr(p)) return false;
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
        "READ_HIT=%d\nFREAD_HIT=%d\nDIRECT_SVC_HIT=%d\n"
        "HOOK_OPENAT=%d\nHOOK_OPEN=%d\nHOOK_FOPEN=%d\n"
        "HOOK_PREAD=%d\nHOOK_MMAP=%d\nHOOK_IOCTL=%d\nHOOK_SYSCALL=%d\n",
        getpid(),hOpenAt.load(),hOpen.load(),hFopen.load(),
        hPread.load(),hMmap.load(),hIoctl.load(),hSyscall.load(),hRead.load(),hFread.load(),
        hDirectSvcOpenat.load(),
        gOpenAt!=nullptr,gOpen!=nullptr,gFopen!=nullptr,
        gPread!=nullptr||gPread64!=nullptr||gPread64Chk!=nullptr,
        gMmap!=nullptr||gMmap64!=nullptr,
        gIoctlImportHooked.load(),gSyscallImportHooked.load());
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
// توابع پروکسی C Hooks
// ---------------------------------------------------------------------------

static int fakeOpenAt(int d,const char* p,int f,...){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        hOpenAt++;
        int fd=makeFakeFd(marker());
        if(fd>=0){LOGI("HOOK openat %s pid=%d fd=%d",p,getpid(),fd);return fd;}
    }
    if(!gOpenAt){errno=ENOSYS;return -1;}
    va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
    return gOpenAt(d,p,f,m);
}

static int fakeOpen(const char* p,int f,...){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        hOpen++;
        int fd=makeFakeFd(marker());
        if(fd>=0){LOGI("HOOK open %s pid=%d fd=%d",p,getpid(),fd);return fd;}
    }
    if(!gOpen){errno=ENOSYS;return -1;}
    va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
    return (f&O_CREAT)?gOpen(p,f,m):gOpen(p,f);
}

static FILE* fakeFopen(const char* p,const char* m){
    if(isKossherPath(p)){
        hFopen++;
        int fd=makeFakeFd(marker());
        if(fd>=0){LOGI("HOOK fopen %s pid=%d fd=%d",p,getpid(),fd);return fdopen(fd,m&&*m?m:"r");}
    }
    return gFopen?gFopen(p,m):nullptr;
}

static ssize_t fakePread(int fd,void* b,size_t n,off_t o){
    hPread++;
    return gPread?gPread(fd,b,n,o):-1;
}

static void* fakeMmap(void* a,size_t n,int p,int f,int fd,off_t o){
    hMmap++;
    return gMmap?gMmap(a,n,p,f,fd,o):(gMmap64?gMmap64(a,n,p,f,fd,o):MAP_FAILED);
}

// ---------------------------------------------------------------------------
// اصلاح پایداری ioctl و syscall (با محافظ g_inside_ioctl)
// ---------------------------------------------------------------------------

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
        if(isKossherPath(path) && (f&O_ACCMODE)!=O_WRONLY){
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
// محاسبه محدوده آدرس libc.so
// ---------------------------------------------------------------------------

static void calculate_libc_range() {
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void* data) -> int {
        if (info->dlpi_name && strstr(info->dlpi_name, "libc.so")) {
            g_libc_start = info->dlpi_addr;
            size_t max_vaddr = 0;
            for (int i = 0; i < info->dlpi_phnum; i++) {
                if (info->dlpi_phdr[i].p_type == PT_LOAD) {
                    size_t vaddr_end = info->dlpi_phdr[i].p_vaddr + info->dlpi_phdr[i].p_memsz;
                    if (vaddr_end > max_vaddr) max_vaddr = vaddr_end;
                }
            }
            g_libc_end = info->dlpi_addr + max_vaddr;
            return 1;
        }
        return 0;
    }, nullptr);
    LOGI("LIBC Memory Range: [%p - %p]", (void*)g_libc_start, (void*)g_libc_end);
}

// ---------------------------------------------------------------------------
// Seccomp BPF با فیلتر هوشمند آدرس libc.so (جلوگیری قطعی از کرش)
// ---------------------------------------------------------------------------

static void sigsys_handler(int code, siginfo_t* info, void* void_context) {
    ucontext_t* ctx = static_cast<ucontext_t*>(void_context);
    uint64_t syscall_num = ctx->uc_mcontext.regs[8]; // x8 در ARM64

    if (syscall_num == __NR_openat) {
        int dirfd = static_cast<int>(ctx->uc_mcontext.regs[0]);
        const char* path = reinterpret_cast<const char*>(ctx->uc_mcontext.regs[1]);
        int flags = static_cast<int>(ctx->uc_mcontext.regs[2]);
        mode_t mode = static_cast<mode_t>(ctx->uc_mcontext.regs[3]);

        if (isKossherPath(path)) {
            hDirectSvcOpenat++;
            int fake_fd = makeFakeFd(marker());
            if (fake_fd >= 0) {
                LOGI("HOOK Direct SVC #0 (__NR_openat) %s pid=%d fd=%d", path, getpid(), fake_fd);
                ctx->uc_mcontext.regs[0] = static_cast<uint64_t>(fake_fd); // ذخیره FD فیک در x0
                ctx->uc_mcontext.pc += 4; // عبور از دستور ۴ بایتی svc #0
                return;
            }
        }

        // اجرای کنترل‌شده از طریق gOpenAt (چون gOpenAt درون libc است، Seccomp آن را اجازه می‌دهد)
        int real_fd = gOpenAt ? gOpenAt(dirfd, path, flags, mode) : openat(dirfd, path, flags, mode);
        ctx->uc_mcontext.regs[0] = static_cast<uint64_t>(real_fd);
        ctx->uc_mcontext.pc += 4;
        return;
    }

    ctx->uc_mcontext.pc += 4;
}

static bool setup_seccomp_svc_hook() {
    calculate_libc_range();
    if (!g_libc_start || !g_libc_end) return false;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsys_handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSYS, &sa, nullptr) != 0) return false;

    uint32_t libc_hi = static_cast<uint32_t>(g_libc_start >> 32);
    uint32_t libc_lo_start = static_cast<uint32_t>(g_libc_start & 0xFFFFFFFF);
    uint32_t libc_lo_end = static_cast<uint32_t>(g_libc_end & 0xFFFFFFFF);

    // فیلتر BPF: چک کردن اینکه آیا دستورالعمل داخل libc.so است یا خیر
    struct sock_filter filter[] = {
        // 1. بررسی شماره سیستم‌کال (__NR_openat = 56)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 6), // اگر openat نیست -> ALLOW

        // 2. بررسی 32 بیت بالایی Instruction Pointer
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, libc_hi, 0, 3), // اگر hi ناهمخوان است -> TRAP

        // 3. بررسی 32 بیت پایینی Instruction Pointer (بین libc_lo_start و libc_lo_end)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, libc_lo_start, 0, 1),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, libc_lo_end, 0, 1),

        // TRAP (برای دستورات svc #0 خارج از libc)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),

        // ALLOW (برای کدهای درون libc.so)
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return false;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) return false;

    LOGI("SECCOMP_SVC_HOOK_INSTALLED_SAFELY");
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

    hookLibcSymbol(gHook,"open",(void*)fakeOpen,(void**)&gOpen,nullptr);
    hookLibcSymbol(gHook,"openat",(void*)fakeOpenAt,(void**)&gOpenAt,&gOpenAtAddr);
    hookLibcSymbol(gHook,"fopen",(void*)fakeFopen,(void**)&gFopen,nullptr);
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
