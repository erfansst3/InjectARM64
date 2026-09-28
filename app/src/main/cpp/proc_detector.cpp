#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <cstring>
#include <string>
#include <atomic>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#define TAG "GspaceHookTest"
using HookFn=void(*)(void*,void*,void**);
using ReadFn=ssize_t(*)(int,void*,size_t);
static HookFn hookApi=nullptr;
static ReadFn readFn=nullptr;
static ReadFn originalRead=nullptr;
static std::atomic<int>probeFd{-1};
static std::atomic<int>probeHits{0};
static bool hooked=false;

static std::string hx(uintptr_t v){
char b[32];snprintf(b,sizeof(b),"0x%llx",(unsigned long long)v);return b;
}

static uintptr_t findHook(){
struct C{uintptr_t a;};
C c{0};
auto cb=[](dl_phdr_info*i,size_t,void*p)->int{
auto*c=(C*)p;
if(i->dlpi_name&&strstr(i->dlpi_name,"libgspace_64.so")){
void*h=dlopen(i->dlpi_name,RTLD_NOW|RTLD_NOLOAD);
if(h){c->a=(uintptr_t)dlsym(h,"MSHookFunction");dlclose(h);}
}
return c->a?1:0;
};
dl_iterate_phdr(cb,&c);
return c.a;
}

static bool resolve(){
if(!hookApi){
uintptr_t a=findHook();
if(!a)return false;
hookApi=(HookFn)a;
}
if(!readFn){
void*a=dlsym(RTLD_DEFAULT,"read");
if(!a)return false;
readFn=(ReadFn)a;
}
return true;
}

static ssize_t hookedRead(int fd,void*buf,size_t n){
ssize_t r=originalRead?originalRead(fd,buf,n):-1;
if(fd==probeFd.load())++probeHits;
return r;
}

static bool install(){
if(hooked)return true;
if(!resolve())return false;
void*o=nullptr;
hookApi((void*)readFn,(void*)hookedRead,&o);
originalRead=(ReadFn)o;
if(!originalRead)return false;
hooked=true;
return true;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_hookEnvironment(JNIEnv*e,jobject){
bool ok=install();
std::string s="PID="+std::to_string(getpid())+"\n";
s+="GSPACE_HOOK_API="+std::string(hookApi?"YES":"NO")+"\n";
s+="LIBC_READ="+std::string(readFn?"YES":"NO")+"\n";
s+="READ_HOOK="+std::string(ok?"INSTALLED":"FAILED")+"\n";
if(readFn)s+="READ_ADDR="+hx((uintptr_t)readFn)+"\n";
return e->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_readEnvironment(JNIEnv*e,jobject){
if(!resolve())return e->NewStringUTF("READ: resolve FAILED");
probeHits=0;
char b[8];
int fd=syscall(SYS_openat,AT_FDCWD,"/dev/zero",O_RDONLY|O_CLOEXEC,0);
if(fd<0)return e->NewStringUTF("READ: open FAILED");
probeFd=fd;
ssize_t n=readFn(fd,b,sizeof(b));
probeFd=-1;
syscall(SYS_close,fd);
std::string s="PID="+std::to_string(getpid())+"\n";
s+="READ_HOOK_INSTALLED="+std::string(hooked?"YES":"NO")+"\n";
s+="READ_RESULT="+std::to_string(n)+"\n";
s+="HOOK_CALLBACK_HITS="+std::to_string(probeHits.load())+"\n";
s+="HOOK_STATUS="+std::string(probeHits.load()>0?"ACTIVE":"NOT_ACTIVE")+"\n";
return e->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_runHookTest(JNIEnv*e,jobject){
return Java_com_erfansst_procmapdetector_MainActivity_hookEnvironment(e,nullptr);
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_getLog(JNIEnv*e,jobject){
return Java_com_erfansst_procmapdetector_MainActivity_readEnvironment(e,nullptr);
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_clearLog(JNIEnv*e,jobject){
return e->NewStringUTF("CLEARED");
}
