package com.erfansst.procmapdetector;
import android.app.*;import android.os.*;import android.content.*;import android.graphics.Color;import android.widget.*;
public class MainActivity extends Activity{
 TextView out;
 static{System.loadLibrary("procmap_test");}
 public void onCreate(Bundle b){super.onCreate(b);LinearLayout r=new LinearLayout(this);r.setOrientation(LinearLayout.VERTICAL);r.setPadding(12,12,12,12);LinearLayout bar=new LinearLayout(this);Button s=new Button(this),t=new Button(this),l=new Button(this),c=new Button(this);s.setText("SCAN");t.setText("TRACE LOADER");l.setText("LOG");c.setText("CLEAR");bar.addView(s,new LinearLayout.LayoutParams(0,-2,1));bar.addView(t,new LinearLayout.LayoutParams(0,-2,1));bar.addView(l,new LinearLayout.LayoutParams(0,-2,1));bar.addView(c,new LinearLayout.LayoutParams(0,-2,1));out=new TextView(this);out.setTextSize(13);out.setTextColor(Color.WHITE);out.setBackgroundColor(Color.rgb(20,20,20));out.setPadding(10,10,10,10);out.setTextIsSelectable(true);ScrollView v=new ScrollView(this);v.addView(out);r.addView(bar);r.addView(v,new LinearLayout.LayoutParams(-1,0,1));setContentView(r);s.setOnClickListener(x->new Thread(()->show(scanGspace())).start());t.setOnClickListener(x->out.setText(traceLoader()));l.setOnClickListener(x->out.setText(getLog()));c.setOnClickListener(x->{clearTrace();out.setText("CLEARED");});}
 void show(String s){runOnUiThread(()->out.setText(s));}
 public native String scanGspace();public native String traceLoader();public native String getLog();public native void clearTrace();
}