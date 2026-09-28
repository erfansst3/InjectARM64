package com.erfansst.procmapdetector;
import android.app.Activity;
import android.os.Bundle;
import android.content.ClipboardManager;
import android.content.ClipData;
import android.content.Context;
import android.graphics.Color;
import android.widget.*;
public class MainActivity extends Activity{
TextView out;
android.os.Handler h=new android.os.Handler(android.os.Looper.getMainLooper());
boolean auto=true;
static{System.loadLibrary("gspace_64");}
public void onCreate(Bundle b){
super.onCreate(b);
LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(16,16,16,16);
LinearLayout bar=new LinearLayout(this);bar.setOrientation(LinearLayout.HORIZONTAL);
Button install=new Button(this);install.setText("INSTALL HOOK");
Button read=new Button(this);read.setText("READ SMAPS");
Button copy=new Button(this);copy.setText("COPY LOG");
bar.addView(install,new LinearLayout.LayoutParams(0,-2,1));
bar.addView(read,new LinearLayout.LayoutParams(0,-2,1));
bar.addView(copy,new LinearLayout.LayoutParams(0,-2,1));
out=new TextView(this);out.setTextSize(12);out.setTextColor(Color.WHITE);out.setBackgroundColor(Color.rgb(20,20,20));out.setPadding(12,12,12,12);out.setTextIsSelectable(true);
ScrollView s=new ScrollView(this);s.addView(out);
root.addView(bar);root.addView(s,new LinearLayout.LayoutParams(-1,0,1));setContentView(root);
install.setOnClickListener(v->runInstall());
read.setOnClickListener(v->runRead());
copy.setOnClickListener(v->copyLog());
runInstall();
h.post(refresh);
}
final Runnable refresh=()->{if(auto){runRead();h.postDelayed(refresh,1000);}};
void runInstall(){new Thread(()->{String r=installHook();runOnUiThread(()->out.setText(r));}).start();}
void runRead(){new Thread(()->{String r=triggerSmaps();runOnUiThread(()->out.setText(r));}).start();}
void copyLog(){String s=out.getText().toString();ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);cm.setPrimaryClip(ClipData.newPlainText("Smaps Hook Log",s));Toast.makeText(this,"Log copied",Toast.LENGTH_SHORT).show();}
@Override protected void onDestroy(){auto=false;h.removeCallbacksAndMessages(null);super.onDestroy();}
public native String installHook();
public native String triggerSmaps();
public native String getLog();
public native String clearLog();
}