package com.erfansst.procmapdetector;

import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import android.content.*;
import android.graphics.Color;
import android.net.Uri;
import android.provider.MediaStore;
import android.widget.*;
import java.io.OutputStream;

public class MainActivity extends Activity{
    TextView out;
    static final String MARK="InjectARM64_HOOK.arm";

    static{System.loadLibrary("procmap_test");}

    @Override public void onCreate(Bundle b){
        super.onCreate(b);
        LinearLayout root=new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(16,16,16,16);

        LinearLayout bar=new LinearLayout(this);
        Button hook=new Button(this);hook.setText("HOOK");
        Button read=new Button(this);read.setText("READ");
        Button reset=new Button(this);reset.setText("RESET");
        Button copy=new Button(this);copy.setText("COPY");
        bar.addView(hook,new LinearLayout.LayoutParams(0,-2,1));
        bar.addView(read,new LinearLayout.LayoutParams(0,-2,1));
        bar.addView(reset,new LinearLayout.LayoutParams(0,-2,1));
        bar.addView(copy,new LinearLayout.LayoutParams(0,-2,1));

        out=new TextView(this);
        out.setTextSize(13);out.setTextColor(Color.WHITE);
        out.setBackgroundColor(Color.rgb(20,20,20));out.setPadding(12,12,12,12);
        out.setTextIsSelectable(true);

        ScrollView scroll=new ScrollView(this);scroll.addView(out);
        root.addView(bar);root.addView(scroll,new LinearLayout.LayoutParams(-1,0,1));
        setContentView(root);

        autoStart();

        hook.setOnClickListener(v->arm());
        read.setOnClickListener(v->read());
        reset.setOnClickListener(v->reset());
        copy.setOnClickListener(v->{
            ClipboardManager cm=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("log",out.getText().toString()));
            Toast.makeText(this,"Copied",Toast.LENGTH_SHORT).show();
        });
    }

    void autoStart(){autoHookIfArmed(isArmed());}

    boolean isArmed(){
        ContentResolver cr=getContentResolver();
        Uri u=MediaStore.Downloads.EXTERNAL_CONTENT_URI;
        try(Cursor c=cr.query(u,new String[]{MediaStore.Downloads._ID},MediaStore.Downloads.DISPLAY_NAME+"=?",new String[]{MARK},null)){
            return c!=null&&c.moveToFirst();
        }catch(Exception e){return false;}
    }

    void arm(){
        try{
            ContentResolver cr=getContentResolver();
            ContentValues v=new ContentValues();
            v.put(MediaStore.Downloads.DISPLAY_NAME,MARK);
            v.put(MediaStore.Downloads.MIME_TYPE,"application/octet-stream");
            v.put(MediaStore.Downloads.RELATIVE_PATH,Environment.DIRECTORY_DOWNLOADS);
            Uri u=cr.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI,v);
            if(u!=null){
                try(OutputStream os=cr.openOutputStream(u)){if(os!=null)os.write(1);}
            }
            boolean ok=installHook();
            out.setText("ARMED=YES\nPROCESS_HOOK="+(ok?"ACTIVE":"FAILED")+"\nPID="+android.os.Process.myPid());
        }catch(Exception e){out.setText("ARM FAILED\n"+e);}
    }

    void reset(){
        ContentResolver cr=getContentResolver();
        try(Cursor c=cr.query(MediaStore.Downloads.EXTERNAL_CONTENT_URI,new String[]{MediaStore.Downloads._ID},MediaStore.Downloads.DISPLAY_NAME+"=?",new String[]{MARK},null)){
            if(c!=null)while(c.moveToNext()){
                long id=c.getLong(0);
                cr.delete(ContentUris.withAppendedId(MediaStore.Downloads.EXTERNAL_CONTENT_URI,id),null,null);
            }
        }catch(Exception e){}
        out.setText("ARMED=NO\nPID="+android.os.Process.myPid());
    }

    void read(){
        boolean armed=isArmed();
        boolean active=autoHookIfArmed(armed);
        new Thread(()->{
            String s=readEnvironment();
            runOnUiThread(()->out.setText("ARMED="+(armed?"YES":"NO")+"\nAUTO_RESULT="+(active?"ACTIVE":"INACTIVE")+"\n"+s));
        }).start();
    }

    public native boolean installHook();
    public native boolean autoHookIfArmed(boolean armed);
    public native String readEnvironment();
    public native String hookEnvironment();
    public native String runHookTest();
    public native String getLog();
    public native String clearLog();
}
