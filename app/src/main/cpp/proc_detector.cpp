#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <string>
#include <cstdio>
#include <mutex>
#include <atomic>

#define TAG "SmapsHookTest"
using MSHookFunctionFn=void(*)(void*,void*,void**);
using OpenAtFn=int(*)(int,const char*,int,mode_t);

static MSHookFunctionFn gMSHookFunction=nullptr;
static OpenAtFn gOriginalOpenAt=nullptr;
static std::mutex gMutex;
static std::string gLog;
static std::atomic<int> gSmapsHits{0};
static std::atomic<int> gOpenAtHits{0};
static bool gInstalled=false;
static bool gApiFound=false;
static std::string gGspacePath;

static void logLine(const std::string& s){
std::lock_guard<std::mutex> lock(gMutex);
gLog+=s+"\n";
__android_log_print(ANDROID_LOG_INFO,TAG,"%s",s.c_str());
}

static bool findLoadedGspace(std::string& path){
FILE* f=fopen("/proc/self/maps","r");
if(!f)return false;
char line[2048];
while(fgets(line,sizeof(line),f)){
if(strstr(line,"libgspace_64.so")){
char* p=strchr(line,'/');
if(p){char* nl=strchr(p,'\n');if(nl)*nl=0;path=p;fclose(f);return true;}
}
}
fclose(f);return false;
}

static int hookOpenAt(int dirfd,const char* pathname,int flags,mode_t mode){
gOpenAtHits++;
if(pathname&&strstr(pathname,"/proc/")&&strstr(pathname,"smaps")){
gSmapsHits++;
logLine(std::string("SMAPS OPEN INTERCEPTED path=")+pathname+" flags="+std::to_string(flags));
}
return gOriginalOpenAt?gOriginalOpenAt(dirfd,pathname,flags,mode):-1;
}

static bool installHook(){
if(gInstalled)return true;
std::string path;
if(!findLoadedGspace(path)){
logLine("GSPACE_API: libgspace_64.so NOT FOUND in /proc/self/maps");
return false;
}
gGspacePath=path;
logLine("GSPACE_API: loaded "+path);
void* ghandle=dlopen(path.c_str(),RTLD_NOW|RTLD_NOLOAD);
if(!ghandle)ghandle=dlopen("libgspace_64.so",RTLD_NOW|RTLD_NOLOAD);
if(!ghandle){
logLine(std::string("GSPACE_API: dlopen failed: ")+dlerror());
return false;
}
gMSHookFunction=reinterpret_cast<MSHookFunctionFn>(dlsym(ghandle,"MSHookFunction"));
if(!gMSHookFunction){
logLine(std::string("GSPACE_API: MSHookFunction export NOT FOUND: ")+(dlerror()?dlerror():"unknown"));
return false;
}
gApiFound=true;
logLine("GSPACE_API: MSHookFunction export FOUND");
void* target=dlsym(RTLD_DEFAULT,"openat");
if(!target){
target=dlsym(RTLD_NEXT,"openat");
}
if(!target){
logLine(std::string("TARGET: openat NOT FOUND: ")+(dlerror()?dlerror():"unknown"));
return false;
}
logLine("TARGET: openat resolved");
void* original=nullptr;
gMSHookFunction(target,reinterpret_cast<void*>(&hookOpenAt),&original);
gOriginalOpenAt=reinterpret_cast<OpenAtFn>(original);
if(!gOriginalOpenAt){
logLine("HOOK: MSHookFunction returned null original");
return false;
}
gInstalled=true;
logLine("HOOK: openat INSTALLED");
return true;
}

static std::string doSmaps(){
int fd=openat(AT_FDCWD,"/proc/self/smaps",O_RDONLY,0);
if(fd<0){
logLine("TRIGGER: openat smaps FAILED errno="+std::to_string(errno));
return "openat failed errno="+std::to_string(errno);
}
char buf[256];ssize_t n=read(fd,buf,sizeof(buf)-1);close(fd);
if(n<0){
logLine("TRIGGER: smaps read FAILED errno="+std::to_string(errno));
return "read failed errno="+std::to_string(errno);
}
buf[n]=0;
logLine("TRIGGER: smaps read OK bytes="+std::to_string(n));
return std::string(buf);
}

static std::string snapshot(){
std::lock_guard<std::mutex> lock(gMutex);
std::string s=gLog;
s+="STATUS\n";
s+="library="+(gGspacePath.empty()?"NOT_FOUND":gGspacePath)+"\n";
s+="MSHookFunction="+std::string(gApiFound?"YES":"NO")+"\n";
s+="openat_hook="+std::string(gInstalled?"YES":"NO")+"\n";
s+="openat_calls="+std::to_string(gOpenAtHits.load())+"\n";
s+="smaps_intercepts="+std::to_string(gSmapsHits.load())+"\n";
return s;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_installHook(JNIEnv* e,jobject){
bool ok=installHook();
return e->NewStringUTF(snapshot().c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_triggerSmaps(JNIEnv* e,jobject){
if(!gInstalled)installHook();
doSmaps();
return e->NewStringUTF(snapshot().c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_getLog(JNIEnv* e,jobject){
return e->NewStringUTF(snapshot().c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_clearLog(JNIEnv* e,jobject){
{
std::lock_guard<std::mutex> lock(gMutex);
gLog.clear();
}
return e->NewStringUTF(snapshot().c_str());
}