#!/usr/bin/env python3
"""Check the installed launch command and press/release input through a PTY."""
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import struct
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parent.parent
R2 = os.environ.get("R2", "r2")
EXT = subprocess.check_output([R2, "-H", "R2_LIBEXT"], text=True).strip()
PLUGIN = ROOT / f"core_tama.{EXT}"


def run(file, events=(), installed=False, duration=0.35):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    previous = termios.tcgetattr(slave)
    args = [R2, "-q", "-c", "r2tama play", str(file)] if installed else [
        R2, "-N", "-q", "-i", str(PLUGIN), "-e", "scr.interactive=true",
        "-e", "scr.color=0", "-c", "r2tama play; r2tama status; pxj 1 @tama.ram; e esil.maxbacksteps", str(file),
    ]
    env = dict(os.environ)
    if not installed:
        env["R2_NOPLUGINS"] = "1"
    proc = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                            start_new_session=True, env=env, cwd=ROOT)
    data = bytearray()
    start = None
    pending = list(events)
    enhanced = any(b"\x1b[" in value for _, value in events)
    quit_sent = False
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.01)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
            now = time.monotonic()
            if start is None and b"r2tama  A=a B=s C=d" in data:
                start = now
            if start is not None:
                while pending and now - start >= pending[0][0]:
                    _, value = pending.pop(0)
                    os.write(master, value)
                if not quit_sent and now - start >= duration:
                    os.write(master, b"q\x1b[113;1:3u" if enhanced else b"q")
                    quit_sent = True
            if proc.poll() is not None:
                break
        assert proc.poll() is not None or quit_sent, data.decode(errors="replace")[-2500:]
        proc.wait(timeout=3)
        assert proc.returncode == 0, data.decode(errors="replace")[-2500:]
        assert start is not None and quit_sent, data.decode(errors="replace")[-2500:]
        output = data.decode(errors="replace")
        if not installed:
            assert "failed=0" in output and "keys=0" in output, output[-2500:]
        assert "ESIL failed" not in output and "Invalid E0C6200" not in output, output[-2500:]
        assert "\x1b[?25h" in output and "\x1b[<u" in output, "terminal not restored"
        assert termios.tcgetattr(slave)[3] & (termios.ICANON | termios.ECHO) == previous[3] & (termios.ICANON | termios.ECHO)
        match = re.search(r"ticks=(\d+)", output)
        elapsed = int(match[1]) / 32768 if match else float(re.findall(r"time=([0-9.]+)s", output)[-1])
        assert elapsed >= duration * 0.7, output[-2500:]
        assert elapsed < (duration + 1) * 1.4, "play ran unpaced"
        return output
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)
        os.close(slave)


# Firmware continually copies the active-low button input into RAM[0].
words = [0] * 6144
words[0x100:0x106] = [0xE0F, 0xE80, 0xB40, 0xEC2, 0xF80, 0x003]
with tempfile.TemporaryDirectory(prefix="r2tama-visual-") as folder:
    mock = Path(folder) / "buttons.bin"
    mock.write_bytes(struct.pack("<6144H", *words))
    for key, pins in [(b"a", 11), (b"s", 13), (b"d", 14)]:
        out = run(mock, [(0.05, key)])
        assert f"[{pins}]" in out, out[-2500:]
    out = run(mock, [(0.02, b"\x1b[?11u"), (0.05, b"\x1b[97;1:1u\x1b[115;1:1u"),
                     (0.15, b"\x1b[97;1:3u")])
    assert "[13]" in out and "press/release" in out, out[-2500:]
    out = run(mock, [(0.02, b"\x1b[?11u"), (0.05, b"\x1b[97;1:1u\x1b[115;1:1u")])
    assert "[9]" in out, out[-2500:]

    out = run(mock, [(0.05, b"m")])
    assert "muted=1" in out and "mute=on" in out, out[-2500:]
    out = run(mock, [(0.05, b"m"), (0.15, b"m")])
    assert "muted=0" in out and "mute=off" in out, out[-2500:]
    out = run(mock, [(0.02, b"\x1b[?11u"),
                     (0.05, b"\x1b[109;1:1u\x1b[109;1:2u\x1b[109;1:3u")])
    assert "muted=1" in out, out[-2500:]

for name in ("p1", "p2"):
    out = run(ROOT / "roms" / f"{name}.bin",
              [(0.15, b"m"), (0.5, b"m"), (0.8, b"m")],
              installed=True, duration=2.0)
    assert "mute=on" in out and "mute=off" in out, out[-2500:]
print("PTY: installed P1/P2 launch, pacing, A/B/C, simultaneous holds, independent releases, mute toggling and terminal restoration passed")
