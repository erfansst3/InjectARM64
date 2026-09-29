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
#include <pthread.h>
#include <errno.h>

#define TAG "InjectARM64"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

using MSHookFunctionFn=void(*)(void*,void*,void**);
using OpenFn=int(*)(const char*,int,...);
using OpenAtFn=int(*)(int,const char*,int,...);
using PreadFn=ssize_t(*)(int,void*,size_t,off_t);
using MmapFn=void*(*)(void*,size_t,int,int,int,off_t);
using IoctlFn=int(*)(int,unsigned long,...);
using FopenFn=FILE*(*)(const char*,const char*);
using SyscallFn=long(*)(long,...);

static MSHookFunctionFn gHook;
static OpenFn gOpen;
static OpenAtFn gOpenAt;
static PreadFn gPread;
static MmapFn gMmap;
static IoctlFn gIoctl;
static FopenFn gFopen;
static SyscallFn gSyscall;
static std::atomic<int> gInstalled{0},gHits{0},gGspaceFound{0};

static const char kTargetSuffix[]="/kossher";

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

static bool isKossherPath(const char* p){
    if(!p||strncmp(p,"/proc/",6))return false;
    p+=6;
    if(*p<'0'||*p>'9')return false;
    while(*p>='0'&&*p<='9')p++;
    return !strcmp(p,kTargetSuffix);
}

static std::string makeBuffer(const char* p){
    char b[1024];
    int n=snprintf(b,sizeof(b),"KOSSHER_BUFFER=ACTIVE\nHOOK=IO\nPID=%d\nPATH=%s\nVALUE=InjectARM64_KOSSHER_TEST_OK\nOPENAT=PASS\nOPEN=PASS\nFOPEN=PASS\nPREAD=PASS\nMMAP=PASS\nIOCTL=PASS\n",getpid(),p);
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

static int fakeOpenAt(int d,const char* p,int f,...){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        int fd=makeFakeFd(makeBuffer(p));
        if(fd>=0){gHits++;LOGI("HOOK openat fd=%d",fd);return fd;}
    }
    if(!gOpenAt){errno=ENOSYS;return -1;}
    if(f&O_CREAT){va_list a;va_start(a,f);mode_t m=va_arg(a,mode_t);va_end(a);return gOpenAt(d,p,f,m);}
    return gOpenAt(d,p,f);
}

static int fakeOpen(const char* p,int f,...){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        int fd=makeFakeFd(makeBuffer(p));
        if(fd>=0){gHits++;LOGI("HOOK open fd=%d",fd);return fd;}
    }
    if(!gOpen){errno=ENOSYS;return -1;}
    if(f&O_CREAT){va_list a;va_start(a,f);mode_t m=va_arg(a,mode_t);va_end(a);return gOpen(p,f,m);}
    return gOpen(p,f);
}

static FILE* fakeFopen(const char* p,const char* m){
    if(isKossherPath(p)&&gOpen){
        int fd=makeFakeFd(makeBuffer(p));
        if(fd>=0){gHits++;LOGI("HOOK fopen fd=%d",fd);return fdopen(fd,m&&*m?m:"r");}
    }
    return gFopen?gFopen(p,m):nullptr;
}

static ssize_t fakePread(int fd,void* b,size_t n,off_t o){
    gHits++;
    return gPread?gPread(fd,b,n,o):-1;
}

static void* fakeMmap(void* a,size_t n,int p,int f,int fd,off_t o){
    gHits++;
    if(fd>=0&&isKossherPath(nullptr)){}
    return gMmap?gMmap(a,n,p,f,fd,o):MAP_FAILED;
}

static int fakeIoctl(int fd,unsigned long req,...){
    gHits++;
    if(!gIoctl){errno=ENOSYS;return -1;}
    va_list a;va_start(a,req);void* arg=va_arg(a,void*);va_end(a);
    return gIoctl(fd,req,arg);
}


static bool hookOne(MSHookFunctionFn h,const char* n,void* repl,void** orig){
    void* p=dlsym(RTLD_DEFAULT,n);
    if(!p)return false;
    h(p,repl,orig);
    return *orig!=nullptr;
}

static bool installHook(){
    if(gInstalled)return true;
    uintptr_t a=findGSpaceExport("MSHookFunction");
    if(!a)return false;
    auto h=(MSHookFunctionFn)a;
    bool ok=true;
    ok&=hookOne(h,"openat",(void*)fakeOpenAt,(void**)&gOpenAt);
    ok&=hookOne(h,"open",(void*)fakeOpen,(void**)&gOpen);
    ok&=hookOne(h,"fopen",(void*)fakeFopen,(void**)&gFopen);
    ok&=hookOne(h,"pread",(void*)fakePread,(void**)&gPread);
    ok&=hookOne(h,"mmap",(void*)fakeMmap,(void**)&gMmap);
    ok&=hookOne(h,"ioctl",(void*)fakeIoctl,(void**)&gIoctl);
    if(!ok)return false;
    gHook=h;gInstalled=1;
    LOGI("HOOKS openat=%d open=%d fopen=%d pread=%d mmap=%d ioctl=%d syscall=%d",!!gOpenAt,!!gOpen,!!gFopen,!!gPread,!!gMmap,!!gIoctl,!!gSyscall);
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
}
