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

#define TAG "InjectARM64"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG,__VA_ARGS__)

using MSHookFunctionFn=void(*)(void*,void*,void**);
using OpenFn=int(*)(const char*,int,...);
using OpenAtFn=int(*)(int,const char*,int,...);
using OpenAt4Fn=int(*)(int,const char*,int,mode_t);
using PreadFn=ssize_t(*)(int,void*,size_t,off_t);
using PreadChkFn=ssize_t(*)(int,void*,size_t,off_t,size_t);
using MmapFn=void*(*)(void*,size_t,int,int,int,off_t);
using IoctlFn=int(*)(int,unsigned long,...);
using Ioctl3Fn=int(*)(int,int,void*);
using FopenFn=FILE*(*)(const char*,const char*);

static MSHookFunctionFn gHook;
static OpenFn gOpen;
static OpenAtFn gOpenAt;
static OpenAt4Fn gOpenAtPrivate;
static PreadFn gPread;
static PreadFn gPread64;
static PreadChkFn gPread64Chk;
static MmapFn gMmap;
static MmapFn gMmap64;
static IoctlFn gIoctl;
static Ioctl3Fn gIoctlPrivate;
static FopenFn gFopen;
static std::atomic<int> gInstalled{0},gGspaceFound{0};
static std::atomic<int> hOpenAt{0},hOpen{0},hFopen{0},hPread{0},hMmap{0},hIoctl{0};

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
    return !strcmp(p,"/kossher");
}

static std::string marker(){
    char b[1200];
    int n=snprintf(b,sizeof(b),
        "KOSSHER_BUFFER=ACTIVE\nPID=%d\n"
        "OPENAT_HIT=%d\nOPEN_HIT=%d\nFOPEN_HIT=%d\n"
        "PREAD_HIT=%d\nMMAP_HIT=%d\nIOCTL_HIT=%d\n"
        "HOOK_OPENAT=%d\nHOOK_OPEN=%d\nHOOK_FOPEN=%d\n"
        "HOOK_PREAD=%d\nHOOK_MMAP=%d\nHOOK_IOCTL=%d\n"
        "DIRECT_SYSCALL=NOT_HOOKABLE\n",
        getpid(),hOpenAt.load(),hOpen.load(),hFopen.load(),
        hPread.load(),hMmap.load(),hIoctl.load(),
        gOpenAt!=nullptr,gOpen!=nullptr,gFopen!=nullptr,
        gPread!=nullptr||gPread64!=nullptr||gPread64Chk!=nullptr,
        gMmap!=nullptr||gMmap64!=nullptr,
        gIoctl!=nullptr||gIoctlPrivate!=nullptr);
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
        int fd=makeFakeFd("KOSSHER_TEST_OPENAT\n");
        if(fd>=0){hOpenAt++;LOGI("HOOK openat %s",p);return fd;}
    }
    if(!gOpenAt){errno=ENOSYS;return -1;}
    va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
    return gOpenAt(d,p,f,m);
}

static int fakeOpen(int dmy,const char* p,int f,...){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        int fd=makeFakeFd("KOSSHER_TEST_OPEN\n");
        if(fd>=0){hOpen++;LOGI("HOOK open %s",p);return fd;}
    }
    if(!gOpen){errno=ENOSYS;return -1;}
    va_list a;va_start(a,f);mode_t m=(f&O_CREAT)?va_arg(a,int):0;va_end(a);
    return (f&O_CREAT)?gOpen(p,f,m):gOpen(p,f);
}

static int fakeOpenAtPrivate(int d,const char* p,int f,mode_t m){
    if(isKossherPath(p)&&(f&O_ACCMODE)!=O_WRONLY){
        int fd=makeFakeFd("KOSSHER_TEST_OPENAT_PRIVATE\n");
        if(fd>=0){hOpenAt++;LOGI("HOOK __openat %s",p);return fd;}
    }
    return gOpenAtPrivate?gOpenAtPrivate(d,p,f,m):-1;
}

static FILE* fakeFopen(const char* p,const char* m){
    if(isKossherPath(p)){
        int fd=makeFakeFd("KOSSHER_TEST_FOPEN\n");
        if(fd>=0){hFopen++;LOGI("HOOK fopen %s",p);return fdopen(fd,m&&*m?m:"r");}
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

static int fakeIoctl(int fd,unsigned long req,...){
    hIoctl++;
    if(!gIoctl){errno=ENOSYS;return -1;}
    va_list a;va_start(a,req);void* arg=va_arg(a,void*);va_end(a);
    return gIoctl(fd,req,arg);
}

static int fakeIoctlPrivate(int fd,int req,void* arg){
    hIoctl++;
    return gIoctlPrivate?gIoctlPrivate(fd,req,arg):-1;
}

static bool hookOne(MSHookFunctionFn h,const char* n,void* repl,void** orig){
    void* p=dlsym(RTLD_DEFAULT,n);
    if(!p)return false;
    h(p,repl,orig);
    bool ok=*orig!=nullptr;
    LOGI("HOOK_INSTALL %s=%d",n,ok);
    return ok;
}

static bool hookFirst(MSHookFunctionFn h,const char* a,const char* b,void* repl,void** orig,const char** picked){
    if(hookOne(h,a,repl,orig)){if(picked)*picked=a;return true;}
    if(b&&hookOne(h,b,repl,orig)){if(picked)*picked=b;return true;}
    return false;
}

static void runSelfTest(){
    char path[64];snprintf(path,sizeof(path),"/proc/%d/kossher",getpid());

    int fd=openat(AT_FDCWD,path,O_RDONLY);
    bool a=checkFd(fd);
    LOGI("TEST OPENAT=%s",a?"PASS":"FAIL");

    fd=open(path,O_RDONLY);
    bool b=checkFd(fd);
    LOGI("TEST OPEN=%s",b?"PASS":"FAIL");

    FILE* fp=fopen(path,"r");
    bool c=false;
    if(fp){char x[64]={0};c=fgets(x,sizeof(x),fp)&&strstr(x,"KOSSHER_TEST");fclose(fp);}
    LOGI("TEST FOPEN=%s",c?"PASS":"FAIL");

    int t=makeFakeFd("KOSSHER_TEST_PREAD\n");
    char x1[64]={0};ssize_t n=t>=0?pread(t,x1,sizeof(x1)-1,0):-1;
    bool d=n>0&&strstr(x1,"KOSSHER_TEST_PREAD");if(t>=0)syscall(SYS_close,t);
    LOGI("TEST PREAD=%s",d?"PASS":"FAIL");

    t=makeFakeFd("KOSSHER_TEST_MMAP\n");
    bool e=false;
    if(t>=0){
        void* q=mmap(nullptr,4096,PROT_READ,MAP_PRIVATE,t,0);
        e=q!=MAP_FAILED&&strstr((char*)q,"KOSSHER_TEST_MMAP")!=nullptr;
        if(q!=MAP_FAILED)munmap(q,4096);
        syscall(SYS_close,t);
    }
    LOGI("TEST MMAP=%s",e?"PASS":"FAIL");

    int pp[2]={-1,-1};
    bool f=false;
    if(pipe(pp)==0){
        const char z[]="12345";
        write(pp[1],z,5);
        int avail=0;
        f=ioctl(pp[0],FIONREAD,&avail)==0&&avail==5;
        close(pp[0]);close(pp[1]);
    }
    LOGI("TEST IOCTL=%s",f?"PASS":"FAIL");

    int ds=(int)syscall(SYS_openat,AT_FDCWD,path,O_RDONLY,0);
    LOGI("TEST DIRECT_SYSCALL=%s",ds>=0?"BYPASS_REAL_PATH":"BYPASS_EXPECTED");
    if(ds>=0)syscall(SYS_close,ds);

    LOGI("COUNTS openat=%d open=%d fopen=%d pread=%d mmap=%d ioctl=%d",hOpenAt.load(),hOpen.load(),hFopen.load(),hPread.load(),hMmap.load(),hIoctl.load());
}

static bool installHook(){
    if(gInstalled)return true;
    uintptr_t a=findGSpaceExport("MSHookFunction");
    if(!a)return false;
    auto h=(MSHookFunctionFn)a;
    const char* picked=nullptr;
    bool ok=true;
    ok&=hookOne(h,"open",(void*)fakeOpen,(void**)&gOpen);
    ok&=hookOne(h,"openat",(void*)fakeOpenAt,(void**)&gOpenAt);
    hookOne(h,"__openat",(void*)fakeOpenAtPrivate,(void**)&gOpenAtPrivate);
    ok&=hookOne(h,"fopen",(void*)fakeFopen,(void**)&gFopen);
    hookFirst(h,"pread","pread64",(void*)fakePread,(void**)&gPread,&picked);
    hookOne(h,"pread64",(void*)fakePread64,(void**)&gPread64);
    hookOne(h,"__pread64_chk",(void*)fakePread64Chk,(void**)&gPread64Chk);
    hookOne(h,"mmap",(void*)fakeMmap,(void**)&gMmap);
    hookOne(h,"mmap64",(void*)fakeMmap64,(void**)&gMmap64);
    hookOne(h,"ioctl",(void*)fakeIoctl,(void**)&gIoctl);
    hookOne(h,"__ioctl",(void*)fakeIoctlPrivate,(void**)&gIoctlPrivate);
    if(!ok)return false;
    gHook=h;gInstalled=1;
    LOGI("HOOKS installed open=%d openat=%d fopen=%d pread=%d mmap=%d ioctl=%d",!!gOpen,!!gOpenAt,!!gFopen,!!gPread||!!gPread64||!!gPread64Chk,!!gMmap||!!gMmap64,!!gIoctl||!!gIoctlPrivate);
    runSelfTest();
    return true;
}

static void* worker(void*){
    LOGI("libmyhook loaded pid=%d",getpid());
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
