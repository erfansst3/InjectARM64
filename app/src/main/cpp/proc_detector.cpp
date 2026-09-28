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
#include <cctype>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

#define TAG "GspaceHookTest"
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

using MSHookFunctionFn=void(*)(void*,void*,void**);
using PutsFn=int(*)(const char*);
using ReadFn=ssize_t(*)(int,void*,size_t);

static MSHookFunctionFn gMSHookFunction=nullptr;
static PutsFn gLibcPuts=nullptr;
static PutsFn gOriginalPuts=nullptr;
static ReadFn gLibcRead=nullptr;
static ReadFn gOriginalRead=nullptr;

static std::mutex gMutex;
static std::string gLog;
static std::atomic<int> gHookHits{0};
static std::atomic<int> gTestRuns{0};
static std::atomic<int> gSmapsHookHits{0};
static std::atomic<long long> gSmapsBytes{0};

static bool gInstalled=false;
static bool gApiFound=false;
static bool gReadInstalled=false;
static std::string gGspacePath;
static uintptr_t gGspaceBase=0;
static uintptr_t gPutsAddr=0;
static uintptr_t gReadAddr=0;
static long gLibcShared=0,gLibcPrivate=0,gLinkerShared=0,gLinkerPrivate=0;
static bool gLibcSeen=false,gLinkerSeen=false;
static std::atomic<int> gTestFd{-1};
static std::atomic<int> gBufferHookHits{0};

static void logLine(const std::string&s){
    std::lock_guard<std::mutex> lock(gMutex);
    gLog+=s+"\n";
    __android_log_print(ANDROID_LOG_INFO,TAG,"%s",s.c_str());
}

static std::string hexAddr(uintptr_t v){
    char b[32];
    std::snprintf(b,sizeof(b),"0x%llx",(unsigned long long)v);
    return b;
}

static int hookedPuts(const char*s){
    ++gHookHits;
    return gOriginalPuts?gOriginalPuts(s):-1;
}

static bool isSmapsFd(int fd){
    char link[64],path[256]={0};
    std::snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);
    long n=syscall(SYS_readlinkat,AT_FDCWD,link,path,sizeof(path)-1);
    if(n<=0)return false;
    path[n]=0;
    return std::strstr(path,"/smaps")!=nullptr;
}

static bool getFdPath(int fd,std::string&out){
    char link[64],path[256]={0};
    std::snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);
    long n=syscall(SYS_readlinkat,AT_FDCWD,link,path,sizeof(path)-1);
    if(n<=0)return false;
    path[n]=0;
    out=path;
    return true;
}

static ssize_t hookedRead(int fd,void*buf,size_t n){
    ssize_t r=gOriginalRead?gOriginalRead(fd,buf,n):-1;
    if(r>0&&isSmapsFd(fd)){
        ++gSmapsHookHits;
        gSmapsBytes+=r;
    }
    if(r>0&&fd==gTestFd.load()){
        char* p=(char*)buf;
        const char* a="Shared_Dirty: 16 kB";
        const char* b="Private_Dirty: 20 kB";
        for(ssize_t i=0;i+strlen(a)<=r;i++)if(!std::memcmp(p+i,a,strlen(a)))std::memcpy(p+i,"Shared_Dirty: 0 kB ",strlen(a));
        for(ssize_t i=0;i+strlen(b)<=r;i++)if(!std::memcmp(p+i,b,strlen(b)))std::memcpy(p+i,"Private_Dirty: 0 kB ",strlen(b));
        ++gBufferHookHits;
    }
    return r;
}

static bool resolveGspaceSymbol(const char*target,uintptr_t&out){
    struct Ctx{const char*target;uintptr_t addr;bool found;std::string*path;uintptr_t*base;};
    Ctx c{target,0,false,&gGspacePath,&gGspaceBase};
    auto cb=[](struct dl_phdr_info*info,size_t,void*opaque)->int{
        auto*c=(Ctx*)opaque;
        if(!info->dlpi_name||!std::strstr(info->dlpi_name,"libgspace_64.so"))return 0;
        if(c->path->empty()){*c->path=info->dlpi_name;*c->base=(uintptr_t)info->dlpi_addr;}
        const ElfW(Phdr)*dynPhdr=nullptr;
        for(int i=0;i<info->dlpi_phnum;i++)if(info->dlpi_phdr[i].p_type==PT_DYNAMIC){dynPhdr=&info->dlpi_phdr[i];break;}
        if(!dynPhdr)return 0;
        auto*dyn=(ElfW(Dyn)*)(info->dlpi_addr+dynPhdr->p_vaddr);
        ElfW(Sym)*symtab=nullptr;const char*strtab=nullptr;size_t strsz=0;ElfW(Word)*hash=nullptr;
        for(auto*d=dyn;d->d_tag!=DT_NULL;d++)switch(d->d_tag){
            case DT_SYMTAB:symtab=(ElfW(Sym)*)(info->dlpi_addr+d->d_un.d_ptr);break;
            case DT_STRTAB:strtab=(const char*)(info->dlpi_addr+d->d_un.d_ptr);break;
            case DT_STRSZ:strsz=(size_t)d->d_un.d_val;break;
            case DT_HASH:hash=(ElfW(Word)*)(info->dlpi_addr+d->d_un.d_ptr);break;
        }
        if(!symtab||!strtab||!strsz||!hash)return 0;
        for(size_t i=0,n=(size_t)hash[1];i<n;i++){
            auto&s=symtab[i];
            if(!s.st_name||s.st_name>=strsz||s.st_shndx==SHN_UNDEF)continue;
            const char*name=strtab+s.st_name;
            if(std::strcmp(name,c->target)||ELF64_ST_TYPE(s.st_info)!=STT_FUNC)continue;
            c->addr=(uintptr_t)(info->dlpi_addr+s.st_value);c->found=true;return 1;
        }
        return 0;
    };
    dl_iterate_phdr(cb,&c);
    if(!c.found)return false;
    out=c.addr;
    return true;
}

static bool resolveHookApi(){
    if(gApiFound)return true;
    uintptr_t a=0;
    if(!resolveGspaceSymbol("MSHookFunction",a)){logLine("MSHookFunction: NOT_FOUND");return false;}
    gMSHookFunction=(MSHookFunctionFn)a;
    gApiFound=true;
    logLine("GSPACE: loaded");
    logLine("GSPACE base="+hexAddr(gGspaceBase));
    logLine("MSHookFunction="+hexAddr(a));
    logLine("HOOK API: READY");
    return true;
}

static bool resolveLibcPuts(){
    void*a=dlsym(RTLD_DEFAULT,"puts");
    if(!a){logLine("libc puts: NOT_FOUND");return false;}
    gLibcPuts=(PutsFn)a;gPutsAddr=(uintptr_t)a;
    Dl_info info{};
    if(dladdr(a,&info)&&info.dli_fname)logLine("libc puts module="+std::string(info.dli_fname));
    logLine("libc puts="+hexAddr(gPutsAddr));
    return true;
}

static bool resolveLibcRead(){
    void*a=dlsym(RTLD_DEFAULT,"read");
    if(!a){logLine("libc read: NOT_FOUND");return false;}
    gLibcRead=(ReadFn)a;gReadAddr=(uintptr_t)a;
    Dl_info info{};
    if(dladdr(a,&info)&&info.dli_fname)logLine("libc read module="+std::string(info.dli_fname));
    logLine("libc read="+hexAddr(gReadAddr));
    return true;
}

static bool installHooks(){
    if(!resolveHookApi()||!resolveLibcPuts()||!resolveLibcRead())return false;
    if(!gInstalled){
        void*o=nullptr;
        gMSHookFunction((void*)gLibcPuts,(void*)&hookedPuts,&o);
        gOriginalPuts=(PutsFn)o;
        if(!gOriginalPuts){logLine("HOOK: libc puts=FAILED");return false;}
        gInstalled=true;
        logLine("HOOK: libc puts=INSTALLED");
    }
    if(!gReadInstalled){
        void*o=nullptr;
        gMSHookFunction((void*)gLibcRead,(void*)&hookedRead,&o);
        gOriginalRead=(ReadFn)o;
        if(!gOriginalRead){logLine("HOOK: libc read=FAILED");return false;}
        gReadInstalled=true;
        logLine("HOOK: libc read=INSTALLED");
    }
    return true;
}

static bool isMapHeader(const char*s){
    if(!std::isxdigit((unsigned char)s[0]))return false;
    const char*d=std::strchr(s,'-');if(!d||d==s)return false;
    const char*sp=std::strchr(d,' ');return sp&&sp>d+1;
}

static void flushMap(int kind,const char*line,long shared,long priv){
    if(!kind)return;
    if(kind==1){
        gLibcShared+=shared;gLibcPrivate+=priv;gLibcSeen=true;
        logLine(std::string("SMAPS libc: ")+line);
        logLine("SMAPS libc Shared_Dirty="+std::to_string(shared)+" kB Private_Dirty="+std::to_string(priv)+" kB");
    }else{
        gLinkerShared+=shared;gLinkerPrivate+=priv;gLinkerSeen=true;
        logLine(std::string("SMAPS linker: ")+line);
        logLine("SMAPS linker Shared_Dirty="+std::to_string(shared)+" kB Private_Dirty="+std::to_string(priv)+" kB");
    }
}

static void parseSmaps(const std::string&data){
    gLibcShared=gLibcPrivate=gLinkerShared=gLinkerPrivate=0;
    gLibcSeen=gLinkerSeen=false;
    size_t p=0;
    int kind=0;
    long shared=0,priv=0;
    std::string header;
    while(p<data.size()){
        size_t e=data.find('\n',p);if(e==std::string::npos)e=data.size();
        std::string line=data.substr(p,e-p);
        if(isMapHeader(line.c_str())){
            flushMap(kind,header.c_str(),shared,priv);
            kind=std::strstr(line.c_str(),"/libc.so")?1:((std::strstr(line.c_str(),"linker64")||std::strstr(line.c_str(),"/linker"))?2:0);
            shared=priv=0;header=line;
        }else if(kind==1||kind==2){
            if(line.rfind("Shared_Dirty:",0)==0)shared=std::strtol(line.c_str()+13,nullptr,10);
            else if(line.rfind("Private_Dirty:",0)==0)priv=std::strtol(line.c_str()+14,nullptr,10);
        }
        p=e<data.size()?e+1:e;
    }
    flushMap(kind,header.c_str(),shared,priv);
    logLine("SMAPS libc TOTAL Shared_Dirty="+std::to_string(gLibcShared)+" kB Private_Dirty="+std::to_string(gLibcPrivate)+" kB");
    logLine("SMAPS linker TOTAL Shared_Dirty="+std::to_string(gLinkerShared)+" kB Private_Dirty="+std::to_string(gLinkerPrivate)+" kB");
}

static void runBufferTest(){
    const char*raw="Mapping: libc.so\nShared_Dirty: 16 kB\nPrivate_Dirty: 20 kB\nMapping: linker64\nShared_Dirty: 16 kB\nPrivate_Dirty: 12 kB\n";
    int fd=(int)syscall(SYS_memfd_create,"vspace_smaps_test",MFD_CLOEXEC);
    if(fd<0){logLine("BUFFER TEST: memfd_create FAILED");return;}
    syscall(SYS_write,fd,raw,strlen(raw));
    syscall(SYS_lseek,fd,0,SEEK_SET);
    gTestFd=fd;
    std::string procPath;
    if(getFdPath(fd,procPath))logLine("BUFFER TEST proc-path="+procPath);
    char buf[512]={0};
    ssize_t n=gLibcRead(fd,buf,sizeof(buf)-1);
    gTestFd=-1;
    syscall(SYS_close,fd);
    if(n<=0){logLine("BUFFER TEST: read FAILED");return;}
    buf[n]=0;
    std::string out(buf,(size_t)n);
    logLine("BUFFER TEST raw=Shared_Dirty: 16 kB Private_Dirty: 20 kB");
    logLine("BUFFER TEST modified="+out.substr(0,out.find('\0')));
    logLine("BUFFER TEST hook_hits="+std::to_string(gBufferHookHits.load()));
    logLine("BUFFER TEST RESULT="+std::string(std::strstr(buf,"Shared_Dirty: 0 kB")&&std::strstr(buf,"Private_Dirty: 0 kB")?"PASS":"FAILED"));
}

static void runSmapsTest(){
    if(!gReadInstalled){
        logLine("SMAPS HOOK: NOT_INSTALLED");
        return;
    }
    gSmapsHookHits=0;gSmapsBytes=0;
    int fd=syscall(SYS_openat,AT_FDCWD,"/proc/self/smaps",O_RDONLY|O_CLOEXEC,0);
    if(fd<0){logLine("SMAPS open: FAILED");return;}
    std::string all;
    char buf[65536];
    for(;;){
        ssize_t n=gLibcRead(fd,buf,sizeof(buf));
        if(n<=0)break;
        all.append(buf,(size_t)n);
        if(all.size()>8*1024*1024)break;
    }
    syscall(SYS_close,fd);
    logLine("SMAPS_READ_HITS="+std::to_string(gSmapsHookHits.load()));
    logLine("SMAPS_READ_BYTES="+std::to_string(gSmapsBytes.load()));
    parseSmaps(all);
    logLine("SMAPS RESULT: "+std::string(gSmapsHookHits>0&&gLibcSeen?"PASS":"FAILED"));
}

static std::string snapshot(){
    std::lock_guard<std::mutex>lock(gMutex);
    std::string s=gLog;
    s+="STATUS\n";
    s+="gspace="+std::string(gGspacePath.empty()?"NOT_FOUND":"YES")+"\n";
    s+="MSHookFunction="+std::string(gApiFound?"YES":"NO")+"\n";
    s+="libc_puts="+std::string(gLibcPuts?"YES":"NO")+"\n";
    s+="libc_read="+std::string(gLibcRead?"YES":"NO")+"\n";
    s+="local_libc_hook="+std::string(gInstalled?"YES":"NO")+"\n";
    s+="local_read_hook="+std::string(gReadInstalled?"YES":"NO")+"\n";
    s+="hook_hits="+std::to_string(gHookHits.load())+"\n";
    s+="buffer_hook_hits="+std::to_string(gBufferHookHits.load())+"\n";
    s+="smaps_hook_hits="+std::to_string(gSmapsHookHits.load())+"\n";
    s+="smaps_libc_shared_dirty="+std::to_string(gLibcShared)+" kB\n";
    s+="smaps_libc_private_dirty="+std::to_string(gLibcPrivate)+" kB\n";
    s+="smaps_linker_shared_dirty="+std::to_string(gLinkerShared)+" kB\n";
    s+="smaps_linker_private_dirty="+std::to_string(gLinkerPrivate)+" kB\n";
    s+="test_runs="+std::to_string(gTestRuns.load())+"\n";
    return s;
}

static std::string runHookTest(){
    if(!installHooks())return snapshot();
    gHookHits=0;
    gBufferHookHits=0;
    const int before=gLibcPuts("LIBC BEFORE HOOK");
    const int after=gLibcPuts("LIBC AFTER HOOK");
    ++gTestRuns;
    logLine("BEFORE result="+std::to_string(before));
    logLine("AFTER result="+std::to_string(after));
    logLine("CALLBACK hits="+std::to_string(gHookHits.load()));
    logLine((after>=0&&gHookHits>0)?"RESULT: PASS":"RESULT: FAILED");
    runBufferTest();
    runSmapsTest();
    return snapshot();
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_runHookTest(JNIEnv*env,jobject){
    auto s=runHookTest();return env->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_getLog(JNIEnv*env,jobject){
    auto s=snapshot();return env->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_clearLog(JNIEnv*env,jobject){
    {std::lock_guard<std::mutex>lock(gMutex);gLog.clear();}
    gHookHits=0;gTestRuns=0;gSmapsHookHits=0;gSmapsBytes=0;gBufferHookHits=0;
    gLibcShared=gLibcPrivate=gLinkerShared=gLinkerPrivate=0;
    gLibcSeen=gLinkerSeen=false;
    return env->NewStringUTF(snapshot().c_str());
}
