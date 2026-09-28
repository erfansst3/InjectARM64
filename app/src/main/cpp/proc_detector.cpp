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

static const char* symType(unsigned t){
switch(t){
case STT_NOTYPE:return "NOTYPE";
case STT_OBJECT:return "OBJECT";
case STT_FUNC:return "FUNC";
case STT_SECTION:return "SECTION";
case STT_FILE:return "FILE";
#ifdef STT_GNU_IFUNC
case STT_GNU_IFUNC:return "IFUNC";
#endif
default:return "OTHER";
}
}

static const char* symBind(unsigned b){
switch(b){
case STB_LOCAL:return "LOCAL";
case STB_GLOBAL:return "GLOBAL";
case STB_WEAK:return "WEAK";
#ifdef STB_GNU_UNIQUE
case STB_GNU_UNIQUE:return "UNIQUE";
#endif
default:return "OTHER";
}
}

static const char* symVis(unsigned v){
switch(v){
case STV_DEFAULT:return "DEFAULT";
case STV_INTERNAL:return "INTERNAL";
case STV_HIDDEN:return "HIDDEN";
case STV_PROTECTED:return "PROTECTED";
default:return "OTHER";
}
}

static bool resolveGspaceSymbol(const char* target,uintptr_t& outAddr){
struct Ctx{const char* target;uintptr_t addr;bool found;};
Ctx ctx{target,0,false};

auto cb=[](struct dl_phdr_info* info,size_t,void* opaque)->int{
Ctx* c=reinterpret_cast<Ctx*>(opaque);
if(!info->dlpi_name||!strstr(info->dlpi_name,"libgspace_64.so"))return 0;

const ElfW(Phdr)* dynPhdr=nullptr;
for(int i=0;i<info->dlpi_phnum;i++){
if(info->dlpi_phdr[i].p_type==PT_DYNAMIC){
dynPhdr=&info->dlpi_phdr[i];
break;
}
}
if(!dynPhdr)return 0;

auto dyn=reinterpret_cast<ElfW(Dyn)*>(info->dlpi_addr+dynPhdr->p_vaddr);
ElfW(Sym)* symtab=nullptr;
const char* strtab=nullptr;
size_t strsz=0;
Elf64_Word* hash=nullptr;

for(ElfW(Dyn)* d=dyn;d->d_tag!=DT_NULL;d++){
if(d->d_tag==DT_SYMTAB) symtab=reinterpret_cast<ElfW(Sym)*>(info->dlpi_addr+d->d_un.d_ptr);
else if(d->d_tag==DT_STRTAB) strtab=reinterpret_cast<const char*>(info->dlpi_addr+d->d_un.d_ptr);
else if(d->d_tag==DT_STRSZ) strsz=(size_t)d->d_un.d_val;
else if(d->d_tag==DT_HASH) hash=reinterpret_cast<ElfW(Word)*>(info->dlpi_addr+d->d_un.d_ptr);
}
if(!symtab||!strtab||!strsz||!hash)return 0;

for(size_t i=0;i<hash[1];i++){
const ElfW(Sym)& s=symtab[i];
if(!s.st_name||s.st_name>=strsz||s.st_shndx==SHN_UNDEF)continue;
const char* n=strtab+s.st_name;
if(strcmp(n,c->target)!=0)continue;
if(ELFW(ST_TYPE)(s.st_info)!=STT_FUNC)continue;
c->addr=(uintptr_t)(info->dlpi_addr+s.st_value);
c->found=true;
return 1;
}
return 0;
};

dl_iterate_phdr(cb,&ctx);
if(!ctx.found)return false;

outAddr=ctx.addr;
return true;
}

static bool resolveHookApi(){
uintptr_t addr=0;
if(!resolveGspaceSymbol("MSHookFunction",addr)){
logLine("ELF MSHookFunction=NOT_FOUND");
return false;
}

gMSHookFunction=reinterpret_cast<MSHookFunctionFn>(addr);
gApiFound=true;

logLine("ELF MSHookFunction=FOUND addr=0x"+
std::to_string((unsigned long long)addr));
logLine("HOOK API: direct-call READY");
return true;
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
if(!findLoadedGspace(path)){
logLine("GSPACE: libgspace_64.so NOT FOUND");
return false;
}

gGspacePath=path;
logLine("GSPACE: loaded");

if(!resolveHookApi())return false;

void* original=nullptr;
gMSHookFunction(reinterpret_cast<void*>(&smapsProbe),
reinterpret_cast<void*>(&hookedSmapsProbe),
&original);

gOriginalProbe=reinterpret_cast<ProbeFn>(original);
if(!gOriginalProbe){
logLine("HOOK: trampoline=NO");
return false;
}

gInstalled=true;
logLine("HOOK: local smapsProbe=INSTALLED");
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