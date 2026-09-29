package com.erfansst.procmapdetector;

import android.app.Activity;
import android.os.Bundle;
import android.content.*;
import android.graphics.Color;
import android.widget.*;

public class MainActivity extends Activity{
    TextView out;

    static{System.loadLibrary("procmap_test");}

    @Override public void onCreate(Bundle b){
        super.onCreate(b);
        LinearLayout root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(16,16,16,16);

        LinearLayout bar=new LinearLayout(this);
        Button hook=new Button(this);hook.setText("HOOK");
        Button read=new Button(this);read.setText("READ");
        Button copy=new Button(this);copy.setText("COPY");
        bar.addView(hook,new LinearLayout.LayoutParams(0,-2,1));
        bar.addView(read,new LinearLayout.LayoutParams(0,-2,1));
        bar.addView(copy,new LinearLayout.LayoutParams(0,-2,1));

        out=new TextView(this);
        out.setTextSize(13);out.setTextColor(Color.WHITE);
        out.setBackgroundColor(Color.rgb(20,20,20));out.setPadding(12,12,12,12);
        out.setTextIsSelectable(true);

        ScrollView scroll=new ScrollView(this);scroll.addView(out);
        root.addView(bar);root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        setContentView(root);

        hook.setOnClickListener(v->{
            String s=hookEnvironment();
            out.setText(s);
        });
        read.setOnClickListener(v->new Thread(()->{
            String s=readEnvironment();
            runOnUiThread(()->out.setText(s));
        }).start());
        copy.setOnClickListener(v->{
            ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("log",out.getText().toString()));
            Toast.makeText(this,"Copied",Toast.LENGTH_SHORT).show();
        });
    }

    public native boolean installHook();
    public native String readEnvironment();
    public native String hookEnvironment();
    public native String runHookTest();
    public native String getLog();
    public native String clearLog();
}
