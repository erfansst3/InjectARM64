#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <string>
#include <cstdio>
#include <mutex>
#include <atomic>

#define TAG "SmapsHookTest"
using MSHookFunctionFn=void(*)(void*,void*,void**);
using ProbeFn=int(*)();

static MSHookFunctionFn gMSHookFunction=nullptr;
static ProbeFn gOriginalProbe=nullptr;
static std::mutex gMutex;
static std::string gLog;
static std::atomic<int> gHookHits{0};
static std::atomic<int> gProbeRuns{0};
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
if(strstr(line,"/libgspace_64.so")){
char* p=strchr(line,'/');
if(p){
char* nl=strchr(p,'\n');
if(nl)*nl=0;
path=p;
fclose(f);
return true;
}
}
}
fclose(f);
return false;
}

static int countSmapsLines(){
int fd=open("/proc/self/smaps",O_RDONLY|O_CLOEXEC);
if(fd<0){
logLine("SMAPS: open FAILED errno="+std::to_string(errno));
return -1;
}
char buf[4096];
std::string data;
for(;;){
ssize_t n=read(fd,buf,sizeof(buf));
if(n<=0)break;
data.append(buf,n);
}
close(fd);
int lines=0;
for(char c:data)if(c=='\n')lines++;
gProbeRuns++;
logLine("SMAPS: read OK lines="+std::to_string(lines));
return lines;
}

__attribute__((noinline)) static int smapsProbe(){
return countSmapsLines();
}

static int hookedSmapsProbe(){
gHookHits++;
logLine("HOOK CALLBACK: smapsProbe intercepted");
int r=gOriginalProbe?gOriginalProbe():-1;
logLine("HOOK CALLBACK: original result="+std::to_string(r));
return r;
}

static bool installHook(){
if(gInstalled)return true;
std::string path;
if(!findLoadedGspace(path)){
logLine("GSPACE_API: libgspace_64.so NOT FOUND");
return false;
}
gGspacePath=path;
logLine("GSPACE_API: found "+path);
void* h=dlopen(path.c_str(),RTLD_NOW|RTLD_NOLOAD);
if(!h){
logLine("GSPACE_API: dlopen failed");
return false;
}
gMSHookFunction=reinterpret_cast<MSHookFunctionFn>(dlsym(h,"MSHookFunction"));
if(!gMSHookFunction){
logLine("GSPACE_API: MSHookFunction export NOT FOUND");
return false;
}
gApiFound=true;
logLine("GSPACE_API: MSHookFunction export FOUND");
void* original=nullptr;
gMSHookFunction(reinterpret_cast<void*>(&smapsProbe),reinterpret_cast<void*>(&hookedSmapsProbe),&original);
gOriginalProbe=reinterpret_cast<ProbeFn>(original);
if(!gOriginalProbe){
logLine("HOOK: original trampoline NOT returned");
return false;
}
gInstalled=true;
logLine("HOOK: local smapsProbe INSTALLED");
return true;
}

static std::string snapshot(){
std::lock_guard<std::mutex> lock(gMutex);
std::string s=gLog;
s+="STATUS\n";
s+="gspace="+std::string(gGspacePath.empty()?"NOT_FOUND":gGspacePath)+"\n";
s+="MSHookFunction="+std::string(gApiFound?"YES":"NO")+"\n";
s+="local_hook="+std::string(gInstalled?"YES":"NO")+"\n";
s+="hook_hits="+std::to_string(gHookHits.load())+"\n";
s+="probe_runs="+std::to_string(gProbeRuns.load())+"\n";
return s;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_installHook(JNIEnv* e,jobject){
installHook();
return e->NewStringUTF(snapshot().c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_triggerSmaps(JNIEnv* e,jobject){
if(!gInstalled)installHook();
if(gInstalled)smapsProbe();
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