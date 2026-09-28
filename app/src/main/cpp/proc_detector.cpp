#include <jni.h>
#include <dirent.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <fcntl.h>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <sys/uio.h>

static bool pidname(const char* n){if(!n||!*n)return false;for(;*n;n++)if(!isdigit((unsigned char)*n))return false;return true;}
static std::string readcmd(const std::string& p){std::ifstream f(p);std::string s;std::getline(f,s,'\0');if(s.empty())s="?";for(char& c:s)if(c=='\n'||c=='\0')c=' ';return s;}

struct MapsResult{bool ok=false;int count=0;std::string libs;};
static MapsResult maps(const std::string& p){
MapsResult r;std::ifstream f(p);if(!f.is_open())return r;r.ok=true;std::string line;std::vector<std::string> libs;
while(std::getline(f,line)){r.count++;auto x=line.find('/');if(x!=std::string::npos){std::string z=line.substr(x);if(z.find(".so")!=std::string::npos&&std::find(libs.begin(),libs.end(),z)==libs.end()&&libs.size()<4)libs.push_back(z);}}
for(auto& z:libs)r.libs+="\n      "+z;return r;
}

static int memopen(const std::string& p,int flags){return open(p.c_str(),flags|O_CLOEXEC);}
static int vmprobe(pid_t pid,bool write){
struct iovec local{nullptr,0},remote{nullptr,0};
errno=0;
ssize_t r=write?process_vm_writev(pid,&local,0,&remote,0,0):process_vm_readv(pid,&local,0,&remote,0,0);
if(r==0)return 1;
if(errno==EPERM||errno==EACCES)return 0;
return -1;
}
static const char* pstat(int v){return v>0?"YES":v==0?"NO":"ERR";}

struct LibReadResult{
bool found=false;
bool read=false;
uintptr_t addr=0;
std::string lib;
unsigned char data[16]{};
int err=0;
ssize_t bytes=0;
};

static LibReadResult read_real_lib(pid_t pid){
LibReadResult r;
std::string mapsPath="/proc/"+std::to_string(pid)+"/maps";
std::ifstream f(mapsPath);
if(!f.is_open())return r;
std::string line;
while(std::getline(f,line)){
unsigned long long start=0,end=0;
char perms[5]={0};
if(sscanf(line.c_str(),"%llx-%llx %4s",&start,&end,perms)!=3)continue;
if(perms[0]!='r'||end<=start||end-start<16)continue;
auto slash=line.find('/');
if(slash==std::string::npos)continue;
std::string path=line.substr(slash);
if(path.find(".so")==std::string::npos)continue;
r.found=true;
r.addr=(uintptr_t)start;
r.lib=path;
struct iovec local{r.data,sizeof(r.data)};
struct iovec remote{(void*)r.addr,sizeof(r.data)};
errno=0;
r.bytes=process_vm_readv(pid,&local,1,&remote,1,0);
r.err=errno;
r.read=(r.bytes==16);
return r;
}
return r;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_scan(JNIEnv* e,jobject){
DIR* d=opendir("/proc");if(!d)return e->NewStringUTF("STATUS=ACCESS_DENIED\nCannot open /proc");
pid_t self=getpid();int seen=0,mapsok=0,mapsfail=0,readopen=0,writeopen=0,readvm=0,writevm=0;pid_t gmsPid=-1;
std::string out="Native process memory permission probe\nSELF PID="+std::to_string(self)+"\n\n";dirent* en;
while((en=readdir(d))){
if(!pidname(en->d_name))continue;
seen++;std::string pid=en->d_name;pid_t target=(pid_t)strtol(en->d_name,nullptr,10);std::string base="/proc/"+pid+"/";
std::string cmd=readcmd(base+"cmdline");
if(gmsPid<0&&cmd.find("com.google.android.gms")==0)gmsPid=target;
auto mr=maps(base+"maps");
if(mr.ok)mapsok++;else mapsfail++;
errno=0;int ro=memopen(base+"mem",O_RDONLY);int re=errno;
errno=0;int wo=memopen(base+"mem",O_WRONLY);int we=errno;
if(ro>=0){readopen++;close(ro);}if(wo>=0){writeopen++;close(wo);}
int rv=vmprobe(target,false),wv=vmprobe(target,true);
if(rv>0)readvm++;if(wv>0)writevm++;
out+="PID "+pid+" | "+cmd+"\n";
out+="  maps="+(mr.ok?std::string("YES"):"NO")+"("+std::to_string(mr.count)+")";
out+="  /mem(R)="+std::string(pstat(ro>=0?1:(re==EACCES||re==EPERM?0:-1)));
out+="  /mem(W)="+std::string(pstat(wo>=0?1:(we==EACCES||we==EPERM?0:-1)));
out+="  vm_read="+std::string(pstat(rv))+"  vm_write="+std::string(pstat(wv))+mr.libs+"\n\n";
}
closedir(d);

out+="SUMMARY\nprocesses="+std::to_string(seen)+"\nmaps readable="+std::to_string(mapsok)+" denied="+std::to_string(mapsfail)+"\n";
out+="/proc/pid/mem read-open="+std::to_string(readopen)+" write-open="+std::to_string(writeopen)+"\n";
out+="process_vm_readv zero-length="+std::to_string(readvm)+" writev zero-length="+std::to_string(writevm)+"\n";
out+="\n=== REAL GMS MEMORY READ ===\n";
if(gmsPid<0){
out+="GMS PID=NOT_FOUND\nREAL READ=NOT_TESTED\n";
}else{
auto rr=read_real_lib(gmsPid);
out+="GMS PID="+std::to_string(gmsPid)+"\n";
if(!rr.found){
out+="library mapping=NOT_FOUND\nREAL READ=NO\n";
}else{
char buf[64];
snprintf(buf,sizeof(buf),"address=0x%llx\n",(unsigned long long)rr.addr);
out+=buf;
out+="library="+rr.lib+"\n";
if(rr.read){
out+="REAL READ=YES\n";
out+="bytes=";
for(int i=0;i<16;i++){
char b[4];
snprintf(b,sizeof(b),"%02X",rr.data[i]);
out+=b;
if(i!=15)out+=" ";
}
out+="\n";
}else{
out+="REAL READ=NO\n";
out+="bytes_read="+std::to_string(rr.bytes)+"\n";
out+="errno="+std::to_string(rr.err)+"\n";
}
}
}

out+="\nZERO-LENGTH TEST IS NON-DESTRUCTIVE: no target byte was transferred.\n";
if(seen==0)out+="STATUS=ACCESS_DENIED\n";
else if((gmsPid>=0)&&read_real_lib(gmsPid).read)out+="STATUS=REAL_CROSS_PROCESS_READ_OK\n";
else if(mapsok>1||readopen>1||writeopen>1)out+="STATUS=PARTIAL\nLimited cross-process access is available.\n";
else out+="STATUS=ACCESS_DENIED\nAndroid/SELinux blocked cross-process memory access beyond the own process.\n";
return e->NewStringUTF(out.c_str());
}