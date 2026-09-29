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

#define TAG "InjectARM64"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG,__VA_ARGS__)

using MSHookFunctionFn=void(*)(void*,void*,void**);
using OpenFn=int(*)(const char*,int,...);
using OpenAtFn=int(*)(int,const char*,int,...);
using PreadFn=ssize_t(*)(int,void*,size_t,off_t);
using OpenAt4Fn=int(*)(int,const char*,int,mode_t);
using Open2Fn=int(*)(const char*,int);
using OpenAt2Fn=int(*)(int,const char*,int);
using PreadChkFn=ssize_t(*)(int,void*,size_t,off_t,size_t);
using MmapFn=void*(*)(void*,size_t,int,int,int,off_t);
using FopenFn=FILE*(*)(const char*,const char*);

static MSHookFunctionFn gHook;
static OpenFn gOpen;
static OpenAtFn gOpenAt;
static Open2Fn gOpen2;
static OpenAt2Fn gOpenAt2;
static Open2Fn gOpen64_2;
static OpenAt2Fn gOpenAt64_2;
static PreadFn gPread;
static PreadFn gPread64;
static PreadChkFn gPread64Chk;
static MmapFn gMmap;
static MmapFn gMmap64;
static FopenFn gFopen;
static std::atomic<int> gInstalled{0},gGspaceFound{0};
static std::atomic<int> hOpenAt{0},hOpen{0},hFopen{0},hPread{0},hMmap{0},hIoctl{0},hRead{0},hFread{0};
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

static bool findModuleByName(const char* needle,GSpaceModule& out){
    auto cb=[](dl_phdr_info* i,size_t,void* p)->int{
        auto* ctx=(std::pair<const char*,GSpaceModule*>*)p;
        if(!i->dlpi_name||!strstr(i->dlpi_name,ctx->first))return 0;
        ctx->second->base=(uintptr_t)i->dlpi_addr;
        for(int n=0;n<i->dlpi_phnum;n++)if(i->dlpi_phdr[n].p_type==PT_DYNAMIC){
            ctx->second->dynamicPhdr=&i->dlpi_phdr[n];
            break;
        }
        return 1;
    };
    std::pair<const char*,GSpaceModule*> ctx{needle,&out};
    dl_iterate_phdr(cb,&ctx);
    return out.base&&out.dynamicPhdr;
}

static uintptr_t findDynamicSymbol(const char* moduleNeedle,const char* name){
    GSpaceModule m;
    if(!findModuleByName(moduleNeedle,m))return 0;
    auto* d=(ElfW(Dyn)*)(m.base+m.dynamicPhdr->p_vaddr);
    ElfW(Sym)* st=nullptr;
    const char* str=nullptr;
    size_t sz=0;
    const ElfW(Word)* sh=nullptr;
    const uint32_t* gh=nullptr;
    for(;d->d_tag!=DT_NULL;d++)switch(d->d_tag){
        case DT_SYMTAB:st=(ElfW(Sym)*)dynPtr(m.base,d->d_un.d_ptr);break;
        case DT_STRTAB:str=(const char*)dynPtr(m.base,d->d_un.d_ptr);break;
        case DT_STRSZ:sz=(size_t)d->d_un.d_val;break;
        case DT_HASH:sh=(const ElfW(Word)*)dynPtr(m.base,d->d_un.d_ptr);break;
        case DT_GNU_HASH:gh=(const uint32_t*)dynPtr(m.base,d->d_un.d_ptr);break;
    }
    if(!st||!str||!sz)return 0;
    size_t n=sysvHashSymbolCount(sh);
    if(!n)n=gnuHashSymbolCount(gh);
    if(!n)return 0;
    for(size_t i=0;i<n;i++){
        const auto& s=st[i];
        if(!s.st_name||s.st_name>=sz||s.st_shndx==SHN_UNDEF)continue;
        if(!strcmp(str+s.st_name,name))
            return m.base+(uintptr_t)s.st_value;
    }
    return 0;
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

static bool isKossherPath(const char* p){
    if(!p||strncmp(p,"/proc/",6))return false;
    p+=6;
    if(*p<'0'||*p>'9')return false;
    while(*p>='0'&&*p<='9')p++;
    return !strcmp(p,"/kossher");
}

static std::string marker(){
    char b[1200];
    int n=snprintf(b,sizeof(b),
        "KOSSHER_BUFFER=ACTIVE\nPID=%d\n"
        "OPENAT_HIT=%d\nOPEN_HIT=%d\nFOPEN_HIT=%d\n"
        "PREAD_HIT=%d\nMMAP_HIT=%d\nIOCTL_HIT=%d\n"
        "READ_HIT=%d\nFREAD_HIT=%d\n"
        "HOOK_OPENAT=%d\nHOOK_OPEN=%d\nHOOK_FOPEN=%d\n"
        "HOOK_PREAD=%d\nHOOK_MMAP=%d\nHOOK_IOCTL=%d\n"
        "ACTIVE_HOOK_SET=open,openat,__open_2,__openat_2,fopen\n"
        "DISABLED_HOOK_SET=read,fread,pread,pread64,mmap,mmap64,ioctl\n"
        "VA_IOUNIFORMER_PRESERVED=__openat,__open\n"
        "DIRECT_SYSCALL=NOT_HOOKABLE\n",
        getpid(),hOpenAt.load(),hOpen.load(),hFopen.load(),
        hPread.load(),hMmap.load(),hIoctl.load(),hRead.load(),hFread.load(),
        gOpenAt!=nullptr,gOpen!=nullptr,gFopen!=nullptr,
        gPread!=nullptr||gPread64!=nullptr||gPread64Chk!=nullptr,
        gMmap!=nullptr||gMmap64!=nullptr);
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

static bool checkFd(int fd){
    if(fd<0)return false;
    char b[64]={0};
    ssize_t n=pread(fd,b,sizeof(b)-1,0);
    bool ok=n>0&&strstr(b,"KOSSHER_TEST")!=nullptr;
    syscall(SYS_close,fd);
    return ok;
}

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

static int fakeOpen2(const char* p,int f){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        hOpen++;
        int fd=makeFakeFd(marker());
        if(fd>=0){LOGI("HOOK __open_2 %s pid=%d fd=%d",p,getpid(),fd);return fd;}
    }
    return gOpen2?gOpen2(p,f):-1;
}

static int fakeOpenAt2(int d,const char* p,int f){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        hOpenAt++;
        int fd=makeFakeFd(marker());
        if(fd>=0){LOGI("HOOK __openat_2 %s pid=%d fd=%d",p,getpid(),fd);return fd;}
    }
    return gOpenAt2?gOpenAt2(d,p,f):-1;
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

static ssize_t fakePread64(int fd,void* b,size_t n,off_t o){
    hPread++;
    return gPread64?gPread64(fd,b,n,o):(gPread?gPread(fd,b,n,o):-1);
}

static ssize_t fakePread64Chk(int fd,void* b,size_t n,off_t o,size_t bos){
    hPread++;
    return gPread64Chk?gPread64Chk(fd,b,n,o,bos):(gPread64?gPread64(fd,b,n,o):(gPread?gPread(fd,b,n,o):-1));
}

static void* fakeMmap(void* a,size_t n,int p,int f,int fd,off_t o){
    hMmap++;
    return gMmap?gMmap(a,n,p,f,fd,o):(gMmap64?gMmap64(a,n,p,f,fd,o):MAP_FAILED);
}

static void* fakeMmap64(void* a,size_t n,int p,int f,int fd,off_t o){
    hMmap++;
    return gMmap64?gMmap64(a,n,p,f,fd,o):(gMmap?gMmap(a,n,p,f,fd,o):MAP_FAILED);
}


static void* gLibc;
static void* gOpenAddr;
static void* gOpenAtAddr;
static void* gOpen2Addr;
static void* gOpenAt2Addr;
static void* gReadAddr;
static void* gPreadAddr;
static void* gFreadAddr;
static void* gFopenAddr;
static void* gMmapAddr;

using ReadFn=ssize_t(*)(int,void*,size_t);
using FreadFn=size_t(*)(void*,size_t,size_t,FILE*);

static ReadFn gRead;
static FreadFn gFread;

static ssize_t fakeRead(int fd,void* b,size_t n){
    hRead++;
    return gRead?gRead(fd,b,n):-1;
}

static size_t fakeFread(void* p,size_t s,size_t n,FILE* f){
    hFread++;
    return gFread?gFread(p,s,n,f):0;
}

static bool hookLibcSymbol(MSHookFunctionFn h,const char* n,void* repl,void** orig,void** addrStore){
    if(!gLibc||!n||!orig)return false;
    void* p=dlsym(gLibc,n);
    if(!p){
        LOGI("LIBC_SYMBOL %s=NOT_FOUND",n);
        return false;
    }
    if(addrStore)*addrStore=p;

    for(int i=0;i<gHookRecordCount;i++){
        if(gHookRecords[i].addr==p){
            *orig=gHookRecords[i].orig;
            LOGI("LIBC_HOOK %s=ALIAS addr=%p orig=%p",n,p,*orig);
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
    LOGI("LIBC_HOOK %s=YES addr=%p orig=%p",n,p,saved);
    return true;
}

static void libcScan(){
    gLibc=dlopen("libc.so",RTLD_NOW);
    if(!gLibc){
        LOGW("libc dlopen failed");
        return;
    }

    hookLibcSymbol(gHook,"open",(void*)fakeOpen,(void**)&gOpen,&gOpenAddr);
    hookLibcSymbol(gHook,"openat",(void*)fakeOpenAt,(void**)&gOpenAt,&gOpenAtAddr);
    hookLibcSymbol(gHook,"__open_2",(void*)fakeOpen2,(void**)&gOpen2,&gOpen2Addr);
    hookLibcSymbol(gHook,"__openat_2",(void*)fakeOpenAt2,(void**)&gOpenAt2,&gOpenAt2Addr);
    hookLibcSymbol(gHook,"__open64_2",(void*)fakeOpen2,(void**)&gOpen64_2,&gOpen2Addr);
    hookLibcSymbol(gHook,"__openat64_2",(void*)fakeOpenAt2,(void**)&gOpenAt64_2,&gOpenAt2Addr);
    // Isolation profile: keep only low-risk file-open hooks while diagnosing
    // the GSpace crash. Do not patch read/pread/fread/mmap yet.
    hookLibcSymbol(gHook,"fopen",(void*)fakeFopen,(void**)&gFopen,&gFopenAddr);
}

static bool installHook(){
    if(gInstalled)return true;
    uintptr_t a=findGSpaceExport("MSHookFunction");
    if(!a)return false;
    gHook=(MSHookFunctionFn)a;
    gInstalled=1;
    libcScan();
    LOGI("HOOKS_PROFILE=OPEN_ONLY");
    LOGI("HOOKS libc=%p open=%d openat=%d __open_2=%d __openat_2=%d fopen=%d",
         gLibc,!!gOpen,!!gOpenAt,!!gOpen2,!!gOpenAt2,!!gFopen);
    LOGI("DISABLED read=fread=pread=pread64=mmap=mmap64=ioctl");
    LOGI("VA_IOUNIFORMER_PRESERVED __openat=YES __open=YES");
    return true;
}

static void* worker(void*){
    LOGI("libmyhook loaded pid=%d tid=%lu",getpid(),(unsigned long)pthread_self());
    for(int i=0;i<300&&!gInstalled.load();i++){
        if(installHook())break;
        usleep(100000);
    }
    if(!gInstalled.load())LOGW("KOSSHER hook timed out; GSpace=%s",gGspaceFound.load()?"FOUND":"NOT_FOUND");
    return nullptr;
}

__attribute__((constructor))
static void onLibraryLoaded(){
    pthread_t t;
    if(pthread_create(&t,nullptr,worker,nullptr)==0)pthread_detach(t);
}
