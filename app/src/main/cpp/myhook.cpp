#include <jni.h>
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

using HookFn=void(*)(void*,void*,void**);
using ReadFn=ssize_t(*)(int,void*,size_t);

static HookFn gHook=nullptr;
static ReadFn gOrigRead=nullptr;
static std::atomic<int> gHits{0};
static std::atomic<int> gInstalled{0};
static const char kMarker[]="\nInjectARM64_HOOK=ACTIVE\n";

struct Module{uintptr_t base=0;const ElfW(Phdr)*dyn=nullptr;};

static bool getGspace(Module&m){
    auto cb=[](dl_phdr_info*i,size_t,void*p)->int{
        auto*m=(Module*)p;
        if(!i->dlpi_name||!strstr(i->dlpi_name,"libgspace_64.so"))return 0;
        m->base=(uintptr_t)i->dlpi_addr;
        for(int n=0;n<i->dlpi_phnum;n++)
            if(i->dlpi_phdr[n].p_type==PT_DYNAMIC){m->dyn=&i->dlpi_phdr[n];break;}
        return 1;
    };
    dl_iterate_phdr(cb,&m);
    return m.base&&m.dyn;
}

static uintptr_t findExport(const char*name){
    Module m;if(!getGspace(m))return 0;
    auto*d=(ElfW(Dyn)*)(m.base+m.dyn->p_vaddr);
    ElfW(Sym)*st=nullptr;const char*str=nullptr;size_t strsz=0;const ElfW(Word)*hash=nullptr;
    for(;d->d_tag!=DT_NULL;d++)switch(d->d_tag){
        case DT_SYMTAB:st=(ElfW(Sym)*)(m.base+d->d_un.d_ptr);break;
        case DT_STRTAB:str=(const char*)(m.base+d->d_un.d_ptr);break;
        case DT_STRSZ:strsz=(size_t)d->d_un.d_val;break;
        case DT_HASH:hash=(const ElfW(Word)*)(m.base+d->d_un.d_ptr);break;
    }
    if(!st||!str||!strsz)return 0;
    size_t count=0;
    if(hash)count=hash[1];
    if(!count){
        void*h=dlopen("libgspace_64.so",RTLD_NOW|RTLD_NOLOAD);
        if(h){void*p=dlsym(h,name);dlclose(h);return (uintptr_t)p;}
        return 0;
    }
    for(size_t i=0;i<count;i++){
        const ElfW(Sym)&s=st[i];
        if(!s.st_name||s.st_name>=strsz||s.st_shndx==SHN_UNDEF)continue;
        if(ELF64_ST_TYPE(s.st_info)!=STT_FUNC)continue;
        if(strcmp(str+s.st_name,name)==0)return m.base+(uintptr_t)s.st_value;
    }
    return 0;
}

static ssize_t hookedRead(int fd,void*buf,size_t n){
    ssize_t r=gOrigRead?gOrigRead(fd,buf,n):syscall(SYS_read,fd,buf,n);
    if(r>0){
        ++gHits;
        const size_t m=sizeof(kMarker)-1;
        if((size_t)r+m<=n){
            memcpy((char*)buf+r,kMarker,m);
            r+=(ssize_t)m;
        }
    }
    return r;
}

static bool install(){
    if(gInstalled.load())return true;
    uintptr_t hookAddr=findExport("MSHookFunction");
    if(!hookAddr)return false;
    auto hook=(HookFn)hookAddr;
    void*readAddr=dlsym(RTLD_DEFAULT,"read");
    if(!readAddr)return false;
    void*orig=nullptr;
    hook(readAddr,(void*)hookedRead,&orig);
    if(!orig)return false;
    gHook=hook;
    gOrigRead=(ReadFn)orig;
    gInstalled=1;
    return true;
}

static void*worker(void*){
    for(int i=0;i<120&&!gInstalled;i++){
        install();
        if(gInstalled)break;
        usleep(100000);
    }
    return nullptr;
}

__attribute__((constructor)) static void init(){
    pthread_t t;
    if(pthread_create(&t,nullptr,worker,nullptr)==0)pthread_detach(t);
}

static std::string test(){
    bool ok=install();
    std::string s;
    s+="PID="+std::to_string(getpid())+"\n";
    s+="GSPACE_MSHookFunction="+std::string(ok||gHook?"FOUND/READY":"NOT_FOUND")+"\n";
    s+="LIBMYHOOK="+std::string(gInstalled?"INSTALLED":"FAILED")+"\n";
    if(!gOrigRead)return s+"RESULT=NO_ORIGINAL_READ\n";
    char b[1024]={0};
    int fd=syscall(SYS_openat,AT_FDCWD,"/proc/self/status",O_RDONLY|O_CLOEXEC,0);
    if(fd<0)return s+"RESULT=OPEN_FAILED\n";
    gHits=0;
    ssize_t n=gOrigRead(fd,b,sizeof(b)-1);
    syscall(SYS_close,fd);
    if(n<0)return s+"RESULT=READ_FAILED\n";
    b[n]=0;
    std::string data(b,(size_t)n);
    bool marker=data.find("InjectARM64_HOOK=ACTIVE")!=std::string::npos;
    s+="BUFFER_HITS="+std::to_string(gHits.load())+"\n";
    s+="MARKER="+std::string(marker?"YES":"NO")+"\n";
    s+="RESULT="+std::string(marker?"REAL_BUFFER_HOOK":"HOOK_NOT_CONFIRMED")+"\n";
    return s;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_erfansst_procmapdetector_MainActivity_nativeMyHookTest(JNIEnv*e,jobject){
    std::string s=test();
    return e->NewStringUTF(s.c_str());
}
