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
using MmapFn=void*(*)(void*,size_t,int,int,int,off_t);
using FopenFn=FILE*(*)(const char*,const char*);
using ReadFn=ssize_t(*)(int,void*,size_t);
using IoctlCallFn=int(*)(int,unsigned long,void*);
using SyscallCallFn=long(*)(long,long,long,long,long,long,long);

static MSHookFunctionFn gHook = nullptr;

// پوینترهای اصلی (Original)
static OpenFn gOpenImport = nullptr;
static OpenAtFn gOpenAtImport = nullptr;
static ReadFn gReadImport = nullptr;
static PreadFn gPreadImport = nullptr;
static MmapFn gMmapImport = nullptr;
static FopenFn gFopen = nullptr;
static IoctlCallFn gIoctlImport = nullptr;
static SyscallCallFn gSyscallImport = nullptr;

static std::atomic<int> gInstalled{0},gGspaceFound{0};
static std::atomic<int> hOpenAt{0},hOpen{0},hFopen{0},hPread{0},hMmap{0},hIoctl{0},hSyscall{0},hRead{0},hFread{0};
static std::atomic<int> hSyscallOpenat{0}, hDirectSvcOpenat{0};

// پرچم‌های جلوگیری از حلقه بازگشتی
static thread_local bool g_inside_hook = false;
static thread_local bool g_inside_ioctl = false;

// محدوده حافظه libc.so
static uintptr_t g_libc_start = 0;
static uintptr_t g_libc_end = 0;

static void* gLibc = nullptr;

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
// توابع پروکسی هوک‌شده سراسری (GOT Hooks)
// ---------------------------------------------------------------------------

static int fakeOpenAt(int d,const char* p,int f,...){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        hOpenAt++;
        int fd=makeFakeFd(marker());
        if(fd>=0){LOGI("HOOK openat %s pid=%d fd=%d",p,getpid(),fd);return fd;}
    }
    if(!gOpenAtImport){
        va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
        return openat(d,p,f,m);
    }
    va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
    return gOpenAtImport(d,p,f,m);
}

static int fakeOpen(const char* p,int f,...){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        hOpen++;
        int fd=makeFakeFd(marker());
        if(fd>=0){LOGI("HOOK open %s pid=%d fd=%d",p,getpid(),fd);return fd;}
    }
    if(!gOpenImport){
        va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
        return (f&O_CREAT)?open(p,f,m):open(p,f);
    }
    va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
    return (f&O_CREAT)?gOpenImport(p,f,m):gOpenImport(p,f);
}

static FILE* fakeFopen(const char* p,const char* m){
    if(isKossherPath(p)){
        hFopen++;
        int fd=makeFakeFd(marker());
        if(fd>=0){LOGI("HOOK fopen %s pid=%d fd=%d",p,getpid(),fd);return fdopen(fd,m&&*m?m:"r");}
    }
    return gFopen?gFopen(p,m):fopen(p,m);
}

static ssize_t fakeRead(int fd,void* b,size_t n){
    hRead++;
    return gReadImport?gReadImport(fd,b,n):read(fd,b,n);
}

static ssize_t fakePread(int fd,void* b,size_t n,off_t o){
    hPread++;
    return gPreadImport?gPreadImport(fd,b,n,o):pread(fd,b,n,o);
}

static void* fakeMmap(void* a,size_t n,int p,int f,int fd,off_t o){
    hMmap++;
    return gMmapImport?gMmapImport(a,n,p,f,fd,o):mmap(a,n,p,f,fd,o);
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
// موتور پچ جدول GOT برای کل اپلیکیشن (Import Hooking)
// ---------------------------------------------------------------------------

static bool patchImportRelas64(
    uintptr_t base,const char* moduleName,
    Elf64_Sym* symtab,const char* strtab,
    Elf64_Rela* relas,size_t count,const char* target,
    void* replacement,void** original,bool& patched){

    constexpr unsigned kGlobDat=1025;
    constexpr unsigned kJumpSlot=1026;
    const size_t pageSize=(size_t)getpagesize();

    for(size_t i=0;i<count;i++){
        const Elf64_Rela& r=relas[i];
        const unsigned type=(unsigned)ELF64_R_TYPE(r.r_info);
        if(type!=kGlobDat && type!=kJumpSlot) continue;

        const size_t symIndex=(size_t)ELF64_R_SYM(r.r_info);
        const char* symName=strtab + symtab[symIndex].st_name;
        if(!symName || strcmp(symName,target)!=0) continue;

        void** slot=(void**)(base+(uintptr_t)r.r_offset);
        void* current=*slot;

        if(current==replacement){
            patched=true;
            continue;
        }

        if(original && *original==nullptr) *original=current;

        const uintptr_t page=(uintptr_t)slot & ~(uintptr_t)(pageSize-1);
        if(mprotect((void*)page,pageSize,PROT_READ|PROT_WRITE)!=0) continue;

        *slot=replacement;
        (void)mprotect((void*)page,pageSize,PROT_READ);
        patched=true;
    }
    return true;
}

static bool patchImportedSymbol64(const dl_phdr_info* info,const char* target,void* replacement,void** original){
    if(!info || !target || !replacement) return false;
    const char* moduleName=(info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : "[main]";

    if(strstr(moduleName,"/libc.so") || strstr(moduleName,"/libmyhook.so")) return false;
    if(strncmp(moduleName,"/data/",6)!=0 && strcmp(moduleName,"[main]")!=0) return false;

    const uintptr_t base=(uintptr_t)info->dlpi_addr;
    const ElfW(Phdr)* dynPhdr=nullptr;

    for(int i=0;i<info->dlpi_phnum;i++){
        if(info->dlpi_phdr[i].p_type==PT_DYNAMIC){
            dynPhdr=&info->dlpi_phdr[i];
            break;
        }
    }
    if(!dynPhdr) return false;

    auto* dyn=(Elf64_Dyn*)(base+dynPhdr->p_vaddr);
    Elf64_Sym* symtab=nullptr;
    const char* strtab=nullptr;
    Elf64_Rela* rela=nullptr;
    size_t relasz=0;
    Elf64_Rela* jmprel=nullptr;
    size_t pltrelsz=0;

    for(;dyn->d_tag!=DT_NULL;dyn++){
        switch(dyn->d_tag){
            case DT_SYMTAB: symtab=(Elf64_Sym*)(base+(uintptr_t)dyn->d_un.d_ptr); break;
            case DT_STRTAB: strtab=(const char*)(base+(uintptr_t)dyn->d_un.d_ptr); break;
            case DT_RELA: rela=(Elf64_Rela*)(base+(uintptr_t)dyn->d_un.d_ptr); break;
            case DT_RELASZ: relasz=(size_t)dyn->d_un.d_val; break;
            case DT_JMPREL: jmprel=(Elf64_Rela*)(base+(uintptr_t)dyn->d_un.d_ptr); break;
            case DT_PLTRELSZ: pltrelsz=(size_t)dyn->d_un.d_val; break;
        }
    }

    if(!symtab || !strtab) return false;
    bool patched=false;

    if(rela && relasz) patchImportRelas64(base,moduleName,symtab,strtab,rela,relasz/sizeof(Elf64_Rela),target,replacement,original,patched);
    if(jmprel && pltrelsz) patchImportRelas64(base,moduleName,symtab,strtab,jmprel,pltrelsz/sizeof(Elf64_Rela),target,replacement,original,patched);

    return patched;
}

struct ImportPatchContext{const char* target;void* replacement;void** original;bool patched;};
static int patchImportedSymbolCallback(dl_phdr_info* info,size_t,void* opaque){
    auto* ctx=(ImportPatchContext*)opaque;
    if(patchImportedSymbol64(info,ctx->target,ctx->replacement,ctx->original)) ctx->patched=true;
    return 0;
}

static void hookAllImports(){
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void*) -> int {
        patchImportedSymbol64(info, "open", (void*)fakeOpen, (void**)&gOpenImport);
        patchImportedSymbol64(info, "openat", (void*)fakeOpenAt, (void**)&gOpenAtImport);
        patchImportedSymbol64(info, "fopen", (void*)fakeFopen, (void**)&gFopen);
        patchImportedSymbol64(info, "read", (void*)fakeRead, (void**)&gReadImport);
        patchImportedSymbol64(info, "pread", (void*)fakePread, (void**)&gPreadImport);
        patchImportedSymbol64(info, "mmap", (void*)fakeMmap, (void**)&gMmapImport);
        patchImportedSymbol64(info, "ioctl", (void*)fakeIoctlImport, (void**)&gIoctlImport);
        patchImportedSymbol64(info, "syscall", (void*)fakeSyscallImport, (void**)&gSyscallImport);
        return 0;
    }, nullptr);
    LOGI("ALL_IMPORT_HOOKS_APPLIED");
}

// ---------------------------------------------------------------------------
// محاسبه محدوده آدرس libc.so و Seccomp
// ---------------------------------------------------------------------------

static void calculate_libc_range() {
    dl_iterate_phdr([](dl_phdr_info* info, size_t, void*) -> int {
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
}

static void sigsys_handler(int, siginfo_t*, void* void_context) {
    ucontext_t* ctx = static_cast<ucontext_t*>(void_context);
    uint64_t syscall_num = ctx->uc_mcontext.regs[8];

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
                ctx->uc_mcontext.regs[0] = static_cast<uint64_t>(fake_fd);
                ctx->uc_mcontext.pc += 4;
                return;
            }
        }

        int real_fd = gOpenAtImport ? gOpenAtImport(dirfd, path, flags, mode) : openat(dirfd, path, flags, mode);
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

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 6),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, libc_hi, 0, 3),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, libc_lo_start, 0, 1),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, libc_lo_end, 0, 1),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
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

static bool installHook(){
    if(gInstalled)return true;
    uintptr_t a=findGSpaceExport("MSHookFunction");
    if(!a)return false;
    gHook=(MSHookFunctionFn)a;
    gInstalled=1;

    gLibc=dlopen("libc.so",RTLD_NOW);
    hookAllImports();
    setup_seccomp_svc_hook();

    LOGI("ALL_HOOKS_AND_GOT_READY");
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
