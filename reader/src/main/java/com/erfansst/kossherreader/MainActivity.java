package com.erfansst.kossherreader;

import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import android.widget.TextView;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        TextView out = new TextView(this);
        out.setTextSize(14);
        out.setPadding(24,24,24,24);
        setContentView(out);
        final String path = "/proc/" + Process.myPid() + "/kossher";
        new Thread(() -> {
            String result;
            try (FileInputStream in = new FileInputStream(path)) {
                byte[] buf = new byte[4096];
                int n = in.read(buf);
                result = n < 0 ? "READ=EOF\nPATH=" + path : new String(buf, 0, n, StandardCharsets.UTF_8);
            } catch (Throwable e) {
                result = "READ=FAILED\nPATH=" + path + "\n" + e.getClass().getSimpleName() + ": " + e.getMessage();
            }
            final String text = result;
            runOnUiThread(() -> out.setText(text));
        }).start();
    }
}
