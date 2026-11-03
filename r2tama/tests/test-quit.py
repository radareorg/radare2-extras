#!/usr/bin/env python3
"""Regression: Kitty quit/release events must not reach radare2's line editor."""
import fcntl
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import termios
import time

ROOT = Path(__file__).resolve().parent.parent
R2 = os.environ.get("R2", "r2")
EXT = subprocess.check_output([R2, "-H", "R2_LIBEXT"], text=True).strip()


def check_quit(release_delay, plain_press=False, from_prompt=False):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 32, 100, 0, 0))
    args = [R2, "-N", "-i", str(ROOT / f"core_tama.{EXT}"), "-e", "scr.color=0",
            "-e", "scr.interactive=true"]
    if not from_prompt:
        args += ["-c", "r2tama play"]
    args += [str(ROOT / "roms/p1.bin")]
    proc = subprocess.Popen(
        args,
        stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
        env=dict(os.environ, R2_NOPLUGINS="1"),
    )
    data = bytearray()
    start = press_time = release_time = tail_time = None
    command_sent = False
    play_sent = not from_prompt
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.005)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                data.extend(chunk)
            now = time.monotonic()
            if not play_sent and b"]>" in data:
                os.write(master, b"r2tama play\r\x1b[13;1:3u")
                play_sent = True
            if start is None and b"r2tama  A=a B=s C=d" in data:
                start = now
                os.write(master, b"\x1b[?3u" if plain_press else b"\x1b[?11u")
            if start is not None and press_time is None and now - start > 0.1:
                os.write(master, b"q" if plain_press else b"\x1b[113;1:1u")
                press_time = now
            if press_time is not None and release_time is None and now - press_time > release_delay:
                os.write(master, b"\x1b[113")
                release_time = now
            if release_time is not None and tail_time is None and now - release_time > 0.04:
                os.write(master, b";1:3u")
                tail_time = now
            if tail_time is not None and not command_sent and now - tail_time > 0.15:
                os.write(master, b"?e QUIT_INPUT_OK\nq!\n")
                command_sent = True
            if proc.poll() is not None:
                # Process exit can precede the final PTY output being read.
                while select.select([master], [], [], 0.05)[0]:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    data.extend(chunk)
                break
        proc.wait(timeout=2)
        output = data.decode(errors="replace")
        assert start is not None, "play never displayed its screen"
        assert "ESIL failed" not in output, output[-2500:]
        assert b"\x1b[<u" in data, "play did not restore the keyboard protocol"
        assert "Unknown fkey" not in output and "Invalid function key" not in output, output[-2500:]
        assert ";1:3u" not in output, output[-2500:]
        assert "QUIT_INPUT_OK\r\n" in output, output[-2500:]
        assert proc.returncode == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        os.close(master)
        os.close(slave)


for delay in (0.02, 0.15, 0.8):
    check_quit(delay)
check_quit(0.15, plain_press=True)
check_quit(0.15, from_prompt=True)
print("PTY: delayed and fragmented Kitty q releases leave a clean, usable prompt")
