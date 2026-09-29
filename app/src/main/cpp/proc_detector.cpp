#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
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

struct GspaceModule {
    uintptr_t base=0;
    const char* path=nullptr;
    const ElfW(Phdr)* dynamicPhdr=nullptr;
};

static std::string hex(uintptr_t v){
    char b[32];
    snprintf(b,sizeof(b),"0x%llx",(unsigned long long)v);
    return b;
}

static int gspaceModuleCb(dl_phdr_info* i,size_t,void* p){
    if(!i->dlpi_name || !strstr(i->dlpi_name,"libgspace_64.so")) return 0;
    auto* m=(GspaceModule*)p;
    m->base=(uintptr_t)i->dlpi_addr;
    m->path=i->dlpi_name;
    for(int n=0;n<i->dlpi_phnum;n++){
        if(i->dlpi_phdr[n].p_type==PT_DYNAMIC){
            m->dynamicPhdr=&i->dlpi_phdr[n];
            break;
        }
    }
    return 1;
}

static bool getGspaceModule(GspaceModule& m){
    dl_iterate_phdr(gspaceModuleCb,&m);
    return m.base!=0 && m.dynamicPhdr!=nullptr;
}

static bool findSymbol(const char*name,uintptr_t&out){
    struct C{const char*n;uintptr_t a;};
    C c{name,0};
    auto cb=[](dl_phdr_info*i,size_t,void*p)->int{
        C*c=(C*)p;
        if(!i->dlpi_name||!strstr(i->dlpi_name,"libgspace_64.so"))return 0;
        const ElfW(Phdr)*ph=nullptr;
        for(int n=0;n<i->dlpi_phnum;n++)
            if(i->dlpi_phdr[n].p_type==PT_DYNAMIC){ph=&i->dlpi_phdr[n];break;}
        if(!ph)return 0;
        auto*d=(ElfW(Dyn)*)(i->dlpi_addr+ph->p_vaddr);
        ElfW(Sym)*st=nullptr;
        const char*str=nullptr;
        size_t sz=0;
        ElfW(Word)*hash=nullptr;
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
            c->a=(uintptr_t)(i->dlpi_addr+s.st_value);
            return 1;
        }
        return 0;
    };
    dl_iterate_phdr(cb,&c);
    out=c.a;
    return out!=0;
}

static bool resolve(){
    if(!gHook){
        uintptr_t a=0;
        if(!findSymbol("MSHookFunction",a))return false;
        gHook=(HookFn)a;
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

static size_t getDynSymCount(const ElfW(Dyn)* d,const uintptr_t base){
    const ElfW(Sym)* symtab=nullptr;
    const ElfW(Word)* hash=nullptr;
    const ElfW(Word)* gnuHash=nullptr;
    for(;d->d_tag!=DT_NULL;d++){
        if(d->d_tag==DT_SYMTAB)symtab=(const ElfW(Sym)*)(base+d->d_un.d_ptr);
        else if(d->d_tag==DT_HASH)hash=(const ElfW(Word)*)(base+d->d_un.d_ptr);
        else if(d->d_tag==DT_GNU_HASH)gnuHash=(const ElfW(Word)*)(base+d->d_un.d_ptr);
    }
    if(hash)return hash[1];
    if(!gnuHash||!symtab)return 0;
    const uint32_t* h=(const uint32_t*)gnuHash;
    uint32_t nbuckets=h[0],symoffset=h[1],bloomSize=h[2];
    if(nbuckets==0)return symoffset;
    const uintptr_t* bloom=(const uintptr_t*)(h+4);
    (void)bloom;
    const uint32_t* buckets=(const uint32_t*)(bloom+bloomSize);
    const uint32_t* chains=buckets+nbuckets;
    uint32_t maxIndex=symoffset;
    for(uint32_t b=0;b<nbuckets;b++){
        uint32_t idx=buckets[b];
        if(idx<symoffset)continue;
        uint32_t cur=idx;
        while(true){
            if(cur>maxIndex)maxIndex=cur;
            uint32_t c=chains[cur-symoffset];
            if(c&1u)break;
            ++cur;
        }
    }
    return (size_t)maxIndex+1;
}

static bool isCandidate(const char*name){
    static const char* keys[]={
        "process","proc","spawn","fork","vfork","clone","exec","zygote",
        "app_process","start","launch","create","load","inject","attach",
        "child","guest","sandbox","runtime","loader","dlopen","dlsym",
        "MSHook","hook","bootstrap","worker"
    };
    if(!name||!*name)return false;
    for(const char* k:keys)if(strcasestr(name,k))return true;
    return false;
}

static std::string scanGspace(){
    GspaceModule m;
    if(!getGspaceModule(m))return "GSPACE_SCAN: libgspace_64.so NOT LOADED\n";

    const ElfW(Dyn)* d=(const ElfW(Dyn)*)(m.base+m.dynamicPhdr->p_vaddr);
    const ElfW(Sym)* symtab=nullptr;
    const char* strtab=nullptr;
    size_t strsz=0;
    for(const ElfW(Dyn)* p=d;p->d_tag!=DT_NULL;p++){
        switch(p->d_tag){
            case DT_SYMTAB:symtab=(const ElfW(Sym)*)(m.base+p->d_un.d_ptr);break;
            case DT_STRTAB:strtab=(const char*)(m.base+p->d_un.d_ptr);break;
            case DT_STRSZ:strsz=(size_t)p->d_un.d_val;break;
        }
    }
    size_t count=getDynSymCount(d,m.base);
    if(!symtab||!strtab||count==0)return "GSPACE_SCAN: dynamic symbols unavailable\n";

    struct Item{std::string name;uintptr_t addr;};
    std::vector<Item> items;
    size_t totalFuncs=0;
    for(size_t n=0;n<count;n++){
        const ElfW(Sym)& s=symtab[n];
        if(!s.st_name||s.st_name>=strsz||s.st_shndx==SHN_UNDEF)continue;
        if(ELF64_ST_TYPE(s.st_info)!=STT_FUNC)continue;
        ++totalFuncs;
        const char* name=strtab+s.st_name;
        if(isCandidate(name)){
            items.push_back({name,m.base+(uintptr_t)s.st_value});
        }
    }

    std::sort(items.begin(),items.end(),[](const Item&a,const Item&b){return a.name<b.name;});
    std::string out;
    out+="GSPACE_SCAN: FOUND\n";
    out+="GSPACE_PATH="+std::string(m.path?m.path:"?")+"\n";
    out+="GSPACE_BASE="+hex(m.base)+"\n";
    out+="DYNSYM_COUNT="+std::to_string(count)+"\n";
    out+="FUNCTION_COUNT="+std::to_string(totalFuncs)+"\n";
    out+="CANDIDATE_COUNT="+std::to_string(items.size())+"\n";
    for(const auto& it:items){
        out+=it.name+" = "+hex(it.addr);
        if(it.name=="MSHookFunction")out+=" [HOOK_API]";
        out+="\n";
    }
    return out;
}

extern "C" JNIEXPORT jboolean JNICALL Java_com_erfansst_procmapdetector_MainActivity_installHook(JNIEnv*,jobject){
    return install()?JNI_TRUE:JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_scanGspace(JNIEnv*e,jobject){
    std::string s=scanGspace();
    return e->NewStringUTF(s.c_str());
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

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_hookEnvironment(JNIEnv*e,jobject){
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
