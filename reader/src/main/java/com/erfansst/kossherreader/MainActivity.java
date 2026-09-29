package com.erfansst.kossherreader;

import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import android.widget.TextView;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);

        TextView out = new TextView(this);
        out.setTextSize(14);
        out.setPadding(24, 24, 24, 24);
        out.setText("READING /proc/" + Process.myPid() + "/kossher ...");
        setContentView(out);

        final String path = "/proc/" + Process.myPid() + "/kossher";

        new Thread(() -> {
            String result;
            try {
                FileInputStream in = new FileInputStream(path);
                byte[] buf = new byte[4096];
                int n;
                try {
                    n = in.read(buf);
                } finally {
                    in.close();
                }

                if (n < 0) {
                    result = "READ=EOF\nPATH=" + path;
                } else {
                    result = "READ=OK\nPATH=" + path + "\n\n"
                            + new String(buf, 0, n, StandardCharsets.UTF_8);
                }
            } catch (Exception e) {
                result = "READ=FAILED\nPATH=" + path + "\n"
                        + e.getClass().getName() + ": " + String.valueOf(e.getMessage());
            }

            final String text = result;
            runOnUiThread(() -> out.setText(text));
        }).start();
    }
}
