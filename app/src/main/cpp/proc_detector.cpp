#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <atomic>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

using HookFn=void(*)(void*,void*,void**);
using ReadFn=ssize_t(*)(int,void*,size_t);

static HookFn gHook=nullptr;
static ReadFn gRead=nullptr;
static std::atomic<int> gProbeFd{-1};
static std::atomic<int> gHits{0};
static bool gInstalled=false;
static const char kMarker[]="\nInjectARM64_HOOK=ACTIVE\n";

static std::string hex(uintptr_t v){
char b[32];snprintf(b,sizeof(b),"0x%llx",(unsigned long long)v);return b;
}

static bool findSymbol(const char*name,uintptr_t&out){
struct C{const char*n;uintptr_t a;};
C c{name,0};
auto cb=[](dl_phdr_info*i,size_t,void*p)->int{
C*c=(C*)p;
if(!i->dlpi_name||!strstr(i->dlpi_name,"libgspace_64.so"))return 0;
const ElfW(Phdr)*ph=nullptr;
for(int n=0;n<i->dlpi_phnum;n++)if(i->dlpi_phdr[n].p_type==PT_DYNAMIC){ph=&i->dlpi_phdr[n];break;}
if(!ph)return 0;
auto*d=(ElfW(Dyn)*)(i->dlpi_addr+ph->p_vaddr);
ElfW(Sym)*st=nullptr;const char*str=nullptr;size_t sz=0;ElfW(Word)*hash=nullptr;
for(;d->d_tag!=DT_NULL;d++)switch(d->d_tag){
case DT_SYMTAB:st=(ElfW(Sym)*)(i->dlpi_addr+d->d_un.d_ptr);break;
case DT_STRTAB:str=(const char*)(i->dlpi_addr+d->d_un.d_ptr);break;
case DT_STRSZ:sz=(size_t)d->d_un.d_val;break;
case DT_HASH:hash=(ElfW(Word)*)(i->dlpi_addr+d->d_un.d_ptr);break;
}
if(!st||!str||!sz||!hash)return 0;
for(size_t n=0;n<hash[1];n++){
auto&s=st[n];
if(!s.st_name||s.st_name>=sz||s.st_shndx==SHN_UNDEF)continue;
if(strcmp(str+s.st_name,c->n)||ELF64_ST_TYPE(s.st_info)!=STT_FUNC)continue;
c->a=(uintptr_t)(i->dlpi_addr+s.st_value);return 1;
}
return 0;
};
dl_iterate_phdr(cb,&c);out=c.a;return out!=0;
}

static bool resolve(){
if(!gHook){
uintptr_t a=0;if(!findSymbol("MSHookFunction",a))return false;gHook=(HookFn)a;
}
if(!gRead)gRead=(ReadFn)dlsym(RTLD_DEFAULT,"read");
return gRead!=nullptr;
}

static ssize_t hookedRead(int fd,void*buf,size_t n){
ssize_t r=syscall(SYS_read,fd,buf,n);
if(fd==gProbeFd.load()&&r>0){
++gHits;
size_t m=sizeof(kMarker)-1;
if((size_t)r+m<=n){
memcpy((char*)buf+r,kMarker,m);
r+=(ssize_t)m;
}
}
return r;
}

static bool install(){
if(gInstalled)return true;
if(!resolve())return false;
void*orig=nullptr;
gHook((void*)gRead,(void*)hookedRead,&orig);
if(!orig)return false;
gInstalled=true;
return true;
}

extern "C" JNIEXPORT jboolean JNICALL Java_com_erfansst_procmapdetector_MainActivity_installHook(JNIEnv*,jobject){
return install()?JNI_TRUE:JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_readEnvironment(JNIEnv*e,jobject){
if(!resolve())return e->NewStringUTF("READ: resolve FAILED");
char b[4096];
gHits=0;
int fd=syscall(SYS_openat,AT_FDCWD,"/proc/self/status",O_RDONLY|O_CLOEXEC,0);
if(fd<0)return e->NewStringUTF("READ: open FAILED");
gProbeFd=fd;
ssize_t n=gRead(fd,b,sizeof(b)-1);
gProbeFd=-1;
syscall(SYS_close,fd);
if(n<0)return e->NewStringUTF("READ: read FAILED");
b[n]=0;
std::string s="PID="+std::to_string(getpid())+"\n";
s+="GSPACE_HOOK_API="+std::string(gHook?"YES":"NO")+"\n";
s+="LIBC_READ="+std::string(gRead?"YES":"NO")+"\n";
s+="READ_HOOK="+std::string(gInstalled?"INSTALLED":"NOT_INSTALLED")+"\n";
s+="READ_ADDR="+hex((uintptr_t)gRead)+"\n";
s+="READ_RESULT="+std::to_string(n)+"\n";
s+="HOOK_CALLBACK_HITS="+std::to_string(gHits.load())+"\n";
s+="HOOK_STATUS="+std::string(gHits.load()?"ACTIVE":"NOT_ACTIVE")+"\n";
s+="PROC_STATUS_DATA:\n"+std::string(b);
return e->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_hookEnvironment(JNIEnv*e,jobject o){
bool ok=install();
std::string s="PID="+std::to_string(getpid())+"\n";
s+="GSPACE_HOOK_API="+std::string(gHook?"YES":"NO")+"\n";
s+="LIBC_READ="+std::string(gRead?"YES":"NO")+"\n";
s+="READ_HOOK="+std::string(ok?"INSTALLED":"FAILED");
return e->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_runHookTest(JNIEnv*e,jobject o){
return Java_com_erfansst_procmapdetector_MainActivity_hookEnvironment(e,o);
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_getLog(JNIEnv*e,jobject o){
return Java_com_erfansst_procmapdetector_MainActivity_readEnvironment(e,o);
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_clearLog(JNIEnv*e,jobject){
return e->NewStringUTF("CLEARED");
}
