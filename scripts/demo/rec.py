#!/usr/bin/env python3
"""Records the two panes of tmux window demo253:rec: one JSON line per changed screen (real text, colours, timing)."""
import json, subprocess, sys, time, os
out, stop = sys.argv[1], sys.argv[1] + ".stop"
def cap(p):
    s = subprocess.run(["tmux", "capture-pane", "-e", "-p", "-t", f"demo253:rec.{p}"], capture_output=True, text=True).stdout
    c = subprocess.run(["tmux", "display", "-p", "-t", f"demo253:rec.{p}", "#{cursor_x},#{cursor_y},#{cursor_flag}"], capture_output=True, text=True).stdout.strip()
    return s, c
t0 = time.time(); last = None
with open(out, "w") as f:
    while not os.path.exists(stop):
        fr = [cap(0), cap(1)]
        if fr != last:
            f.write(json.dumps({"t": round(time.time() - t0, 2), "p": fr}) + "\n"); f.flush(); last = fr
        time.sleep(0.08)
