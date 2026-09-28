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
HandlerProxy timer=new HandlerProxy();
boolean auto=true;
static{System.loadLibrary("gspace_64");}
public void onCreate(Bundle b){
super.onCreate(b);
LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(16,16,16,16);
LinearLayout bar=new LinearLayout(this);bar.setOrientation(LinearLayout.HORIZONTAL);
Button scan=new Button(this);scan.setText("REFRESH");
Button copy=new Button(this);copy.setText("COPY LOG");
Button toggle=new Button(this);toggle.setText("AUTO: ON");
bar.addView(scan,new LinearLayout.LayoutParams(0,-2,1));bar.addView(copy,new LinearLayout.LayoutParams(0,-2,1));bar.addView(toggle,new LinearLayout.LayoutParams(0,-2,1));
out=new TextView(this);out.setTextSize(12);out.setTextColor(Color.WHITE);out.setBackgroundColor(Color.rgb(20,20,20));out.setPadding(12,12,12,12);out.setTextIsSelectable(true);
ScrollView s=new ScrollView(this);s.addView(out);
root.addView(bar);root.addView(s,new LinearLayout.LayoutParams(-1,0,1));setContentView(root);
scan.setOnClickListener(v->runScan());
copy.setOnClickListener(v->copyLog());
toggle.setOnClickListener(v->{auto=!auto;toggle.setText(auto?"AUTO: ON":"AUTO: OFF");if(auto)timer.start();else timer.stop();});
runScan();timer.start();
}
void runScan(){new Thread(()->{String r=scan();runOnUiThread(()->out.setText(r));}).start();}
void copyLog(){String s=out.getText().toString();ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);cm.setPrimaryClip(ClipData.newPlainText("GSpace diagnostic log",s));Toast.makeText(this,"Full log copied",Toast.LENGTH_SHORT).show();}
@Override protected void onDestroy(){timer.stop();super.onDestroy();}
public native String scan();
class HandlerProxy{
final android.os.Handler h=new android.os.Handler(android.os.Looper.getMainLooper());
final Runnable r=()->{if(auto){runScan();h.postDelayed(r,1000);}};
void start(){h.removeCallbacks(r);h.postDelayed(r,1000);}
void stop(){h.removeCallbacks(r);}
}
}