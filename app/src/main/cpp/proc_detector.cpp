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
static std::atomic<int> gProbeHookHits{0};
static std::atomic<int> gProbeFd{-1};

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

static bool isEnvironFd(int fd){
    std::string p;
    return getFdPath(fd,p)&&p.find("/proc/")!=std::string::npos&&p.find("/environ")!=std::string::npos;
}

static ssize_t hookedRead(int fd,void*buf,size_t n){
    ssize_t r=gOriginalRead?gOriginalRead(fd,buf,n):-1;
    if(r>=0&&fd==gProbeFd.load())++gProbeHookHits;
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
extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_hookEnvironment(JNIEnv*env,jobject){
    bool ok=installHooks();
    std::string s="PID="+std::to_string(getpid())+"\nHOOK="+std::string(ok?"PASS":"FAILED")+"\n";
    if(ok) s+="libc_read="+hexAddr(gLibcRead)+"\n";
    logLine("ENV HOOK PID="+std::to_string(getpid())+" "+(ok?"PASS":"FAILED"));
    return env->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_readEnvironment(JNIEnv*env,jobject){
    if(!resolveLibcRead())return env->NewStringUTF("READ: libc read NOT_FOUND");
    gProbeHookHits=0;
    char b[4]={0};
    int fd=syscall(SYS_openat,AT_FDCWD,"/dev/zero",O_RDONLY|O_CLOEXEC,0);
    if(fd<0)return env->NewStringUTF("READ: probe open FAILED");
    gProbeFd=fd;
    ssize_t n=gLibcRead(fd,b,sizeof(b));
    gProbeFd=-1;
    syscall(SYS_close,fd);
    std::string s="PID="+std::to_string(getpid())+"\n";
    s+="read="+hexAddr(gLibcRead)+"\n";
    s+="read_result="+std::to_string(n)+"\n";
    s+="HOOK_CALLBACK_HITS="+std::to_string(gProbeHookHits.load())+"\n";
    s+="HOOK_STATUS="+std::string(gProbeHookHits.load()>0?"ACTIVE":"NOT_ACTIVE")+"\n";
    logLine("READ PROBE PID="+std::to_string(getpid())+" hits="+std::to_string(gProbeHookHits.load()));
    return env->NewStringUTF(s.c_str());
}


