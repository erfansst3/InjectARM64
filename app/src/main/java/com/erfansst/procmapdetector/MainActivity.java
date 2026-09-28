package com.erfansst.procmapdetector;

import android.app.Activity;
import android.os.Bundle;
import android.content.ClipboardManager;
import android.content.ClipData;
import android.content.Context;
import android.graphics.Color;
import android.widget.*;

public class MainActivity extends Activity {
    TextView out;

    static {
        System.loadLibrary("procmap_test");
    }

    @Override
    public void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(16, 16, 16, 16);

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);

        Button test = new Button(this);
        test.setText("RUN HOOK + SMAPS");

        Button copy = new Button(this);
        copy.setText("COPY LOG");

        bar.addView(test, new LinearLayout.LayoutParams(0, -2, 1));
        bar.addView(copy, new LinearLayout.LayoutParams(0, -2, 1));

        out = new TextView(this);
        out.setTextSize(13);
        out.setTextColor(Color.WHITE);
        out.setBackgroundColor(Color.rgb(20, 20, 20));
        out.setPadding(12, 12, 12, 12);
        out.setTextIsSelectable(true);

        ScrollView scroll = new ScrollView(this);
        scroll.addView(out);

        root.addView(bar);
        root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root);

        test.setOnClickListener(v -> runTest());
        copy.setOnClickListener(v -> copyLog());
    }

    void runTest() {
        new Thread(() -> {
            String result = runHookTest();
            runOnUiThread(() -> out.setText(result));
        }).start();
    }

    void copyLog() {
        String s = out.getText().toString();
        ClipboardManager cm =
                (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("GSpace Hook + Smaps Log", s));
        Toast.makeText(this, "Log copied", Toast.LENGTH_SHORT).show();
    }

    public native String runHookTest();
    public native String getLog();
    public native String clearLog();
}
