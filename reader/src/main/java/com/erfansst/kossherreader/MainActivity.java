package com.erfansst.kossherreader;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Typeface;
import android.widget.*;

import java.io.*;
import java.net.*;

public final class MainActivity extends Activity {
    private final int port = 39391;
    private TextView out;

    @Override public void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24,24,24,24);

        Button read = new Button(this);
        read.setText("READ BUFFER");
        root.addView(read, new LinearLayout.LayoutParams(-1,-2));

        out = new TextView(this);
        out.setTextSize(14);
        out.setTypeface(Typeface.MONOSPACE);
        out.setText("Waiting...");
        ScrollView scroll = new ScrollView(this);
        scroll.addView(out);
        root.addView(scroll, new LinearLayout.LayoutParams(-1,0,1));

        setContentView(root);

        read.setOnClickListener(v -> readBuffer());
    }

    private void readBuffer() {
        out.setText("READING...");
        new Thread(() -> {
            String result;
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress("127.0.0.1", port), 1500);
                DataInputStream in = new DataInputStream(s.getInputStream());
                int len = in.readInt();
                if (len < 0 || len > 65536) throw new IOException("bad length=" + len);
                byte[] data = new byte[len];
                in.readFully(data);
                result = new String(data, "UTF-8");
            } catch (Throwable e) {
                result = "READ FAILED\n" + e.getClass().getSimpleName() + ": " + e.getMessage();
            }
            final String text = result;
            runOnUiThread(() -> out.setText(text));
        }).start();
    }
}
