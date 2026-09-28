#include <jni.h>
#include <dirent.h>
#include <unistd.h>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
static bool pidname(const char* n){if(!n||!*n)return false;for(;*n;n++)if(!isdigit((unsigned char)*n))return false;return true;}
static std::string readcmd(const std::string& p){std::ifstream f(p);std::string s;std::getline(f,s,'\0');if(s.empty())s="?";for(char& c:s)if(c=='\n'||c=='\0')c=' ';return s;}
static std::string maps(const std::string& p,int& count,bool& ok){std::ifstream f(p);if(!f.is_open()){ok=false;return "";}ok=true;std::string line,out;std::vector<std::string> libs;while(std::getline(f,line)){count++;auto x=line.find('/');if(x!=std::string::npos){std::string z=line.substr(x);if(z.find(".so")!=std::string::npos&&std::find(libs.begin(),libs.end(),z)==libs.end()&&libs.size()<12)libs.push_back(z);}}for(auto& z:libs)out+="\n      "+z;return out;}
extern "C" JNIEXPORT jstring JNICALL Java_com_erfansst_procmapdetector_MainActivity_scan(JNIEnv* e,jobject){DIR* d=opendir("/proc");if(!d)return e->NewStringUTF("STATUS=ACCESS_DENIED\nCannot open /proc");pid_t self=getpid();int seen=0,readable=0,failed=0;std::string out="Native /proc maps detector\nPID(getpid)="+std::to_string(self)+"\n\n";dirent* en;while((en=readdir(d))){if(!pidname(en->d_name))continue;seen++;std::string pid=en->d_name,base="/proc/"+pid+"/",cmd=readcmd(base+"cmdline");int n=0;bool ok=false;std::string libs=maps(base+"maps",n,ok);if(ok){readable++;out+="PID "+pid+" | "+cmd+" | maps="+std::to_string(n)+libs+"\n\n";}else failed++;}closedir(d);out+="\nSUMMARY\nprocess entries="+std::to_string(seen)+"\nreadable maps="+std::to_string(readable)+"\nmap access failures="+std::to_string(failed)+"\n";if(readable<=1&&seen>1)out+="STATUS=ACCESS_DENIED\nAndroid/SELinux blocked other process maps. Own process may still be readable.\n";else if(readable==0)out+="STATUS=ACCESS_DENIED\nNo process maps were readable.\n";else if(failed)out+="STATUS=PARTIAL\nSome process maps were blocked.\n";else out+="STATUS=OK\nAll discovered process maps were readable.\n";return e->NewStringUTF(out.c_str());}