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
#include <link.h>
#include <elf.h>
#include <algorithm>
#include <cctype>

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

static int phdrCallback(struct dl_phdr_info* info,size_t,void*){
if(info->dlpi_name&&strstr(info->dlpi_name,"libgspace_64.so")){
logLine("GSPACE_ELF: loaded="+std::string(info->dlpi_name));
logLine("GSPACE_ELF: base=0x"+std::to_string((unsigned long long)info->dlpi_addr));
}
return 0;
}

static void enumerateLoaded(){
dl_iterate_phdr(phdrCallback,nullptr);
}

static bool relevant(const char* n){
if(!n)return false;
std::string s=n;
std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return (char)std::tolower(c);});
return s.find("hook")!=std::string::npos||s.find("substrate")!=std::string::npos||s.find("sandhook")!=std::string::npos||s.find("inline")!=std::string::npos||s.find("xhook")!=std::string::npos;
}

static void enumerateExports(){
auto cb=[](struct dl_phdr_info* info,size_t,void*)->int{
if(!info->dlpi_name||!strstr(info->dlpi_name,"libgspace_64.so"))return 0;
const ElfW(Phdr)* dynPhdr=nullptr;
for(int i=0;i<info->dlpi_phnum;i++)if(info->dlpi_phdr[i].p_type==PT_DYNAMIC){dynPhdr=&info->dlpi_phdr[i];break;}
if(!dynPhdr)return 0;
ElfW(Dyn)* dyn=reinterpret_cast<ElfW(Dyn)*>(info->dlpi_addr+dynPhdr->p_vaddr);
ElfW(Sym)* symtab=nullptr;
const char* strtab=nullptr;
size_t strsz=0;
ElfW(Word)* hash=nullptr;
ElfW(Word)* ghash=nullptr;
for(ElfW(Dyn)* d=dyn;d->d_tag!=DT_NULL;d++){
if(d->d_tag==DT_SYMTAB)symtab=reinterpret_cast<ElfW(Sym)*>(info->dlpi_addr+d->d_un.d_ptr);
else if(d->d_tag==DT_STRTAB)strtab=reinterpret_cast<const char*>(info->dlpi_addr+d->d_un.d_ptr);
else if(d->d_tag==DT_STRSZ)strsz=d->d_un.d_val;
else if(d->d_tag==DT_HASH)hash=reinterpret_cast<ElfW(Word)*>(info->dlpi_addr+d->d_un.d_ptr);
else if(d->d_tag==DT_GNU_HASH)ghash=reinterpret_cast<ElfW(Word)*>(info->dlpi_addr+d->d_un.d_ptr);
}
if(!symtab||!strtab||!strsz)return 0;
size_t count=hash?hash[1]:0;
if(!count&&ghash){
uint32_t nb=ghash[0],symoff=ghash[1],maskwords=ghash[2];
const uintptr_t* bloom=reinterpret_cast<const uintptr_t*>(ghash+4);
const uint32_t* buckets=reinterpret_cast<const uint32_t*>(bloom+maskwords);
const uint32_t* chains=buckets+nb;
for(uint32_t b=0;b<nb;b++){
uint32_t idx=buckets[b];
if(idx<symoff)continue;
for(;;idx++){
count=std::max(count,(size_t)idx+1);
if(chains[idx-symoff]&1)break;
if(count>1000000)return 0;
}
}
}
if(!count||count>1000000)return 0;
logLine("GSPACE_EXPORTS: begin");
size_t shown=0;
for(size_t i=0;i<count;i++){
const ElfW(Sym)& s=symtab[i];
if(!s.st_name||s.st_name>=strsz||s.st_shndx==SHN_UNDEF)continue;
unsigned bind=ELF64_ST_BIND(s.st_info);
if(bind==STB_LOCAL)continue;
const char* n=strtab+s.st_name;
logLine("EXPORT "+std::string(n)+" value=0x"+std::to_string((unsigned long long)s.st_value));
if(relevant(n))logLine("HOOK_RELATED "+std::string(n));
shown++;
}
logLine("GSPACE_EXPORTS: count="+std::to_string(shown));
return 1;
};
dl_iterate_phdr(cb,nullptr);
}

static int countSmapsLines(){
int fd=open("/proc/self/smaps",O_RDONLY|O_CLOEXEC);
if(fd<0){logLine("SMAPS: open FAILED errno="+std::to_string(errno));return -1;}
char buf[4096];
std::string data;
for(;;){ssize_t n=read(fd,buf,sizeof(buf));if(n<=0)break;data.append(buf,n);}
close(fd);
int lines=0;
for(char c:data)if(c=='\n')lines++;
gProbeRuns++;
logLine("SMAPS: read OK lines="+std::to_string(lines));
return lines;
}

__attribute__((noinline)) static int smapsProbe(){return countSmapsLines();}

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
if(!findLoadedGspace(path)){logLine("GSPACE_API: libgspace_64.so NOT FOUND");return false;}
gGspacePath=path;
logLine("GSPACE_API: found "+path);
enumerateLoaded();
enumerateExports();
void* h=dlopen("libgspace_64.so",RTLD_NOW|RTLD_NOLOAD);
if(h){
logLine("GSPACE_API: basename dlopen OK");
gMSHookFunction=reinterpret_cast<MSHookFunctionFn>(dlsym(h,"MSHookFunction"));
}
if(!gMSHookFunction){
gMSHookFunction=reinterpret_cast<MSHookFunctionFn>(dlsym(RTLD_DEFAULT,"MSHookFunction"));
if(gMSHookFunction)logLine("GSPACE_API: RTLD_DEFAULT MSHookFunction FOUND");
}
if(!gMSHookFunction){logLine("GSPACE_API: MSHookFunction NOT RESOLVED");return false;}
gApiFound=true;
logLine("GSPACE_API: MSHookFunction export FOUND");
void* original=nullptr;
gMSHookFunction(reinterpret_cast<void*>(&smapsProbe),reinterpret_cast<void*>(&hookedSmapsProbe),&original);
gOriginalProbe=reinterpret_cast<ProbeFn>(original);
if(!gOriginalProbe){logLine("HOOK: original trampoline NOT returned");return false;}
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

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_installHook(JNIEnv* e,jobject){installHook();return e->NewStringUTF(snapshot().c_str());}
extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_triggerSmaps(JNIEnv* e,jobject){if(!gInstalled)installHook();if(gInstalled)smapsProbe();return e->NewStringUTF(snapshot().c_str());}
extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_getLog(JNIEnv* e,jobject){return e->NewStringUTF(snapshot().c_str());}
extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_clearLog(JNIEnv* e,jobject){{std::lock_guard<std::mutex> lock(gMutex);gLog.clear();}return e->NewStringUTF(snapshot().c_str());}