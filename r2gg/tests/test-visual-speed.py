#!/usr/bin/env python3
"""Measure paced Columns playback through a PTY, optionally with real r2au output."""
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time

root = Path(__file__).resolve().parent.parent
r2 = os.environ.get("R2", "r2")
extension = subprocess.check_output([r2, "-H", "R2_LIBEXT"], text=True).strip()
plugin = str(root / f"core_gg.{extension}")
rom = sys.argv[1] if len(sys.argv) > 1 else "/tmp/columns.gg"
duration = float(os.environ.get("R2GG_DURATION", "12"))
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
args = [r2, "-N", "-q", "-i", plugin]
if os.environ.get("R2AU_PLUGIN"):
    args += ["-i", os.environ["R2AU_PLUGIN"]]
args += ["-e", "scr.interactive=true", "-e", "scr.color=3", "-c",
         "r2gg play;?e VISUAL_DONE;r2gg status;q!", rom]
process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                           start_new_session=True, env=dict(os.environ, R2_NOPLUGINS="1"))
output = bytearray()
start = None
quit_at = None
quit_sent = False
events = [(6, b"F"), (8, b"F"), (10, b"F")]
try:
    deadline = time.monotonic() + duration + 10
    while time.monotonic() < deadline:
        if select.select([master], [], [], .005)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            output.extend(chunk)
        now = time.monotonic()
        if start is None and b"r2gg | hjkl" in output:
            start = now
            quit_at = now + duration
        if start:
            while events and now - start >= events[0][0]:
                os.write(master, events.pop(0)[1])
        if quit_at and now >= quit_at and not quit_sent:
            os.write(master, b"q")
            quit_sent = True
        if process.poll() is not None:
            break
    text = output.decode(errors="replace")
    assert start is not None and "VISUAL_DONE" in text, text[-2000:]
    assert "ESIL failed" not in text and "Game Gear stopped" not in text, text[-2000:]
    status = re.search(r"cycles=(\d+) frames=(\d+) bank=\d+ audio=(\d+)", text)
    assert status, text[-2000:]
    cycles, frames, audio = map(int, status.groups())
    speed = cycles / 3579545 / duration
    print(f"wall={duration:.1f}s cycles={cycles} frames={frames} audio={audio} speed={speed:.2f}x")
    assert .95 < speed < 1.10, "paced play execution did not sustain real time"
    if os.environ.get("R2AU_PLUGIN"):
        assert "Cannot open audio" not in text and "Audio needs" not in text, text[-2000:]
finally:
    if process.poll() is None:
        process.kill()
    process.wait()
    os.close(master)
    os.close(slave)
