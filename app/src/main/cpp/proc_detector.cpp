#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <algorithm>
#include <atomic>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <cstdio>
#include <cstring>
using HookFn=void(*)(void*,void*,void**);
static HookFn gHook=nullptr;
extern "C" void* gNativeLoadOrig=nullptr;
extern "C" void* gDlopenCIOrig=nullptr;
extern "C" void* gDlopenCIVOrig=nullptr;
extern "C" void* gDlopenCIVVOrig=nullptr;
extern "C" void* gOnSoLoadedOrig=nullptr;
static bool gTraceInstalled=false;
static thread_local bool gTraceBusy=false;
static std::atomic<unsigned> gTraceSeq{0};
static std::atomic<unsigned> gHitCI{0};
static std::atomic<unsigned> gHitCIV{0};
static std::atomic<unsigned> gHitCIVV{0};
static std::atomic<unsigned> gHitOnSoLoaded{0};
static std::atomic<unsigned> gHitNativeLoad{0};
static char gTraceBuf[64][256];
extern "C" void traceNativeLoad();
extern "C" void traceDlopenCI();
extern "C" void traceDlopenCIV();
extern "C" void traceDlopenCIVV();
extern "C" void traceOnSoLoaded();
struct GspaceModule{uintptr_t base=0;const char*path=nullptr;const ElfW(Phdr)*dynamicPhdr=nullptr;};
static std::string hex(uintptr_t v){char b[32];snprintf(b,sizeof(b),"0x%llx",(unsigned long long)v);return b;}
static int moduleCb(dl_phdr_info*i,size_t,void*p){if(!i->dlpi_name||!strstr(i->dlpi_name,"libgspace_64.so"))return 0;auto*m=(GspaceModule*)p;m->base=(uintptr_t)i->dlpi_addr;m->path=i->dlpi_name;for(int n=0;n<i->dlpi_phnum;n++)if(i->dlpi_phdr[n].p_type==PT_DYNAMIC){m->dynamicPhdr=&i->dlpi_phdr[n];break;}return 1;}
static bool getModule(GspaceModule&m){dl_iterate_phdr(moduleCb,&m);return m.base&&m.dynamicPhdr;}
static size_t symCount(const ElfW(Dyn)*d,uintptr_t base){const ElfW(Word)*h=nullptr;const uint32_t*g=nullptr;for(;d->d_tag!=DT_NULL;d++)if(d->d_tag==DT_HASH)h=(const ElfW(Word)*)(base+d->d_un.d_ptr);else if(d->d_tag==DT_GNU_HASH)g=(const uint32_t*)(base+d->d_un.d_ptr);if(h)return h[1];if(!g)return 0;uint32_t nb=g[0],off=g[1],bs=g[2];const uintptr_t*b=(const uintptr_t*)(g+4);const uint32_t*bucket=(const uint32_t*)(b+bs),*chain=bucket+nb;uint32_t max=off;for(uint32_t i=0;i<nb;i++){uint32_t x=bucket[i];if(x<off)continue;for(;;x++){if(x>max)max=x;if(chain[x-off]&1)break;}}return max+1;}
static bool findSymbol(const char*name,uintptr_t&out){GspaceModule m;if(!getModule(m))return false;auto*d=(const ElfW(Dyn)*)(m.base+m.dynamicPhdr->p_vaddr);const ElfW(Sym)*st=nullptr;const char*str=nullptr;size_t sz=0;for(auto*p=d;p->d_tag!=DT_NULL;p++){if(p->d_tag==DT_SYMTAB)st=(const ElfW(Sym)*)(m.base+p->d_un.d_ptr);else if(p->d_tag==DT_STRTAB)str=(const char*)(m.base+p->d_un.d_ptr);else if(p->d_tag==DT_STRSZ)sz=p->d_un.d_val;}size_t n=symCount(d,m.base);if(!st||!str||!n)return false;for(size_t i=0;i<n;i++){auto&s=st[i];if(!s.st_name||s.st_name>=sz||s.st_shndx==SHN_UNDEF||ELF64_ST_TYPE(s.st_info)!=STT_FUNC)continue;if(!strcmp(str+s.st_name,name)){out=m.base+s.st_value;return true;}}return false;}
static bool resolve(){if(!gHook){uintptr_t a;if(!findSymbol("MSHookFunction",a))return false;gHook=(HookFn)a;}return true;}
static std::string scanGspace(){GspaceModule m;if(!getModule(m))return "GSPACE_SCAN: libgspace_64.so NOT LOADED\n";auto*d=(const ElfW(Dyn)*)(m.base+m.dynamicPhdr->p_vaddr);const ElfW(Sym)*st=nullptr;const char*str=nullptr;size_t sz=0;for(auto*p=d;p->d_tag!=DT_NULL;p++){if(p->d_tag==DT_SYMTAB)st=(const ElfW(Sym)*)(m.base+p->d_un.d_ptr);else if(p->d_tag==DT_STRTAB)str=(const char*)(m.base+p->d_un.d_ptr);else if(p->d_tag==DT_STRSZ)sz=p->d_un.d_val;}size_t n=symCount(d,m.base);if(!st||!str||!n)return "GSPACE_SCAN: dynamic symbols unavailable\n";static const char*keys[]={"process","proc","spawn","fork","vfork","clone","exec","zygote","app_process","start","launch","create","load","inject","attach","child","guest","sandbox","runtime","loader","dlopen","dlsym","MSHook","hook","bootstrap","worker"};std::vector<std::string>v;size_t funcs=0;for(size_t i=0;i<n;i++){auto&s=st[i];if(!s.st_name||s.st_name>=sz||s.st_shndx==SHN_UNDEF||ELF64_ST_TYPE(s.st_info)!=STT_FUNC)continue;funcs++;const char*x=str+s.st_name;for(auto*k:keys)if(strcasestr(x,k)){v.push_back(std::string(x)+" = "+hex(m.base+s.st_value));break;}}std::sort(v.begin(),v.end());std::string o="GSPACE_SCAN: FOUND\nGSPACE_PATH="+(m.path?std::string(m.path):"?")+"\nGSPACE_BASE="+hex(m.base)+"\nDYNSYM_COUNT="+std::to_string(n)+"\nFUNCTION_COUNT="+std::to_string(funcs)+"\nCANDIDATE_COUNT="+std::to_string(v.size())+"\n";for(auto&s:v)o+=s+"\n";return o;}
static std::string readName(uintptr_t p){
 if(!p)return "<null>";
 char b[192]={0};
 struct iovec l{b,sizeof(b)-1},r{(void*)p,sizeof(b)-1};
 long n=syscall(SYS_process_vm_readv,getpid(),&l,1,&r,1,0);
 if(n<=0)return "<unreadable>";
 b[n]=0;
 return b;
}
static void traceLog(const char*n,uintptr_t a0,uintptr_t a1,uintptr_t ra,const char*s=nullptr){
 if(gTraceBusy)return;
 gTraceBusy=true;
 unsigned i=gTraceSeq.fetch_add(1);
 if(s)snprintf(gTraceBuf[i%64],sizeof(gTraceBuf[0]),"TRACE %s pid=%d tid=%ld ra=%s name=%s a0=%s a1=%s",n,getpid(),syscall(SYS_gettid),hex(ra).c_str(),s,hex(a0).c_str(),hex(a1).c_str());
 else snprintf(gTraceBuf[i%64],sizeof(gTraceBuf[0]),"TRACE %s pid=%d tid=%ld ra=%s a0=%s a1=%s",n,getpid(),syscall(SYS_gettid),hex(ra).c_str(),hex(a0).c_str(),hex(a1).c_str());
 __android_log_print(ANDROID_LOG_INFO,"InjectARM64","%s",gTraceBuf[i%64]);
 gTraceBusy=false;
}
extern "C" void traceLogEvent(int id,uintptr_t*r){
 static const char*names[]={"?","new_nativeLoad","new_dlopen_CI","new_do_dlopen_CIV","new_do_dlopen_CIVV","onSoLoaded"};
 if(id<1||id>5)return;
 switch(id){
   case 1:gHitNativeLoad.fetch_add(1);break;
   case 2:gHitCI.fetch_add(1);break;
   case 3:gHitCIV.fetch_add(1);break;
   case 4:gHitCIVV.fetch_add(1);break;
   case 5:gHitOnSoLoaded.fetch_add(1);break;
 }
 traceLog(names[id],r[0],r[1],r[15],id>=2?readName(r[0]).c_str():nullptr);
}
static bool hookOne(const char*n,void*rep,void**orig){uintptr_t a;if(!findSymbol(n,a))return false;gHook((void*)a,rep,orig);return *orig!=nullptr;}
static std::string traceLoader(){if(!resolve())return "TRACE_LOADER=FAILED\nMSHookFunction=NO";bool a=hookOne("new_nativeLoad",(void*)traceNativeLoad,&gNativeLoadOrig);bool b=hookOne("new_dlopen_CI",(void*)traceDlopenCI,&gDlopenCIOrig);bool d=hookOne("new_do_dlopen_CIV",(void*)traceDlopenCIV,&gDlopenCIVOrig);bool v=hookOne("new_do_dlopen_CIVV",(void*)traceDlopenCIVV,&gDlopenCIVVOrig);bool e=hookOne("onSoLoaded",(void*)traceOnSoLoaded,&gOnSoLoadedOrig);int c=a+b+d+v+e;gTraceInstalled=c>0;return "TRACE_LOADER="+std::string(gTraceInstalled?"ACTIVE":"FAILED")+"\nMSHookFunction=YES\nnew_nativeLoad="+(a?"HOOKED":"NOT_FOUND")+"\nnew_dlopen_CI="+(b?"HOOKED":"NOT_FOUND")+"\nnew_do_dlopen_CIV="+(d?"HOOKED":"NOT_FOUND")+"\nnew_do_dlopen_CIVV="+(v?"HOOKED":"NOT_FOUND")+"\nonSoLoaded="+(e?"HOOKED":"NOT_FOUND")+"\nHOOK_COUNT="+std::to_string(c);}
extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_scanGspace(JNIEnv*e,jobject){auto s=scanGspace();return e->NewStringUTF(s.c_str());}
extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_traceLoader(JNIEnv*e,jobject){auto s=traceLoader();return e->NewStringUTF(s.c_str());}
extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_getLog(JNIEnv*e,jobject){
 std::string s="PID="+std::to_string(getpid())+"\nTRACE_LOADER="+(gTraceInstalled?"ACTIVE":"INACTIVE")+"\n";
 s+="HITS nativeLoad="+std::to_string(gHitNativeLoad.load());
 s+=" CI="+std::to_string(gHitCI.load());
 s+=" CIV="+std::to_string(gHitCIV.load());
 s+=" CIVV="+std::to_string(gHitCIVV.load());
 s+=" onSoLoaded="+std::to_string(gHitOnSoLoaded.load())+"\n";
 unsigned end=gTraceSeq.load(),start=end>64?end-64:0;
 for(unsigned i=start;i<end;i++){s+=gTraceBuf[i%64];s+="\n";}
 return e->NewStringUTF(s.c_str());
}
extern "C" JNIEXPORT void JNICALL Java_com_erfansst_procmapdetector_MainActivity_clearTrace(JNIEnv*,jobject){
 gTraceSeq=0;
 gHitNativeLoad=0;
 gHitCI=0;
 gHitCIV=0;
 gHitCIVV=0;
 gHitOnSoLoaded=0;
}
