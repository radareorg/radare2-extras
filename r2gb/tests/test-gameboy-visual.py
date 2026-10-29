#!/usr/bin/env python3
"""Exercise r2gb play through a real terminal; no ROM fixture is required."""

import fcntl
import os
import pty
from pathlib import Path
import re
import select
import struct
import subprocess
import termios
import time


R2 = os.environ.get("R2", "r2")
PLUGIN = os.environ.get("R2GB_PLUGIN")
if not PLUGIN:
    extension = subprocess.check_output([R2, "-H", "R2_LIBEXT"], text=True).strip()
    PLUGIN = str(Path(__file__).resolve().parent.parent / f"core_gb.{extension}")
PROGRAM = "3e20e000f000ea00c03e10e000f000ea01c0c30001"
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[78]")


def visual(key, columns=80, rows=24, pattern=False, duration=0.02, events=(), sleep_us=None):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    commands = [f"wx {PROGRAM} @0x100"]
    if sleep_us is not None:
        commands += [f"e gb.usleep={sleep_us}"]
    if pattern:
        commands += [
            "r2gb", "wx 00 @0xff40", "wox ff @0x10000!69120",
            "wx 000000 @0x10000",
        ]
    commands += [
        "r2gb play", "?e VISUAL_DONE", "pxj 2 @0xc000",
        "r2gb status", "e esil.maxbacksteps", "q!",
    ]
    process = subprocess.Popen(
        [R2, "-N", "-q", "-i", PLUGIN, "-e", "scr.interactive=true", "-e",
         f"scr.color={3 if pattern else 0}", "-c", ";".join(commands), "malloc://0x8000"],
        stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
        env=dict(os.environ, R2_NOPLUGINS="1"),
    )
    data = bytearray()
    pressed = False
    quit_at = None
    pressed_at = None
    pending_events = list(events)
    deadline = time.monotonic() + 10
    try:
        while time.monotonic() < deadline:
            if select.select([master], [], [], 0.005)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
            if not pressed and b"r2gb | hjkl" in data:
                os.write(master, key.encode())
                pressed = True
                pressed_at = time.monotonic()
                if key != "\x03":
                    quit_at = time.monotonic() + duration
            while pressed_at and pending_events and time.monotonic() >= pressed_at + pending_events[0][0]:
                _, event = pending_events.pop(0)
                os.write(master, event.encode())
            if quit_at and time.monotonic() >= quit_at:
                os.write(master, b"q")
                quit_at = None
            if process.poll() is not None:
                break
        if process.poll() is None:
            raise AssertionError("play mode failed to exit within ten seconds")
        output = data.decode(errors="replace")
        assert pressed and "VISUAL_DONE" in output, output[-2000:]
        assert "Game Boy stopped" not in output, output[-2000:]
        assert process.returncode == 0, output[-2000:]
        return output
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        os.close(master)
        os.close(slave)


def test_keys():
    cases = {
        "h": (0xed, 0xdf), "j": (0xe7, 0xdf), "k": (0xeb, 0xdf),
        "l": (0xee, 0xdf), "a": (0xef, 0xde), "s": (0xef, 0xdd),
        "D": (0xef, 0xdb), "F": (0xef, 0xd7), "\x03": (0xef, 0xdf),
    }
    for key, expected in cases.items():
        output = visual(key)
        match = re.search(r"\[(\d+),(\d+)\]", output)
        assert match, output[-2000:]
        actual = tuple(map(int, match.groups()))
        assert actual == expected, (key, actual, expected)
        assert re.search(r"cycles=[1-9]\d*", output), output[-2000:]
        assert "256" in output.split("VISUAL_DONE", 1)[1], output[-2000:]
    print("All eight button mappings, nonblocking stepping, q, and Ctrl-C: OK")


def test_held_buttons():
    pressed = "\x1b[?11u\x1b[104;1:1u\x1b[97;1:1u"
    cases = [
        ((), (0xed, 0xde)),
        (((0.2, "\x1b[97;1:3u"),), (0xed, 0xdf)),
        (((0.2, "\x1b[104;1:3u"),), (0xef, 0xde)),
        (((0.2, "\x1b[104;1:3u\x1b[97;1:3u"),), (0xef, 0xdf)),
    ]
    for events, expected in cases:
        output = visual(pressed, duration=0.7, events=events)
        match = re.search(r"\[(\d+),(\d+)\]", output)
        assert match, output[-2000:]
        assert tuple(map(int, match.groups())) == expected, output[-2000:]
        assert "\x1b[>11u" in output and "\x1b[<u" in output
    output = visual("\x1b[?11u\x1b[104;1:1u", duration=0.5,
                    events=((0.2, "\x1b[113;1:1u"),))
    assert "VISUAL_DONE" in output
    output = visual("ha", duration=0.8, events=((0.3, "h"), (0.6, "h")))
    match = re.search(r"\[(\d+),(\d+)\]", output)
    assert match and tuple(map(int, match.groups())) == (0xed, 0xdf), output[-2000:]
    assert "input=timed" in output
    print("Simultaneous holds, independent releases, long holds, and keyboard-mode restoration: OK")


def test_pixels():
    output = visual("q", 180, 80, True)
    assert "\x1b[38;2;0;0;0m\x1b[48;2;255;255;255m▀" in output
    assert "▀" * 160 in ANSI.sub("", output)
    output = visual("q", 80, 40, True)
    assert "\x1b[48;2;255;255;255m\x1b[38;2;0;0;0m⠁" in output
    assert "⠀" * 80 in ANSI.sub("", output)
    output = visual("q", 80, 24, True)
    assert any("\u2800" <= ch <= "\u28ff" for ch in output)
    print("Native pixels, full-resolution braille, and filtered small-screen output: OK")


def test_frame_pacing():
    times = []
    for sleep_us in (0, 16000, 1000000):
        output = visual("", duration=0.4, sleep_us=sleep_us)
        match = re.search(r"cycles=(\d+) frames=", output)
        assert match, output[-2000:]
        elapsed = int(match[1]) / 4194304
        assert .35 < elapsed < .5, (sleep_us, elapsed)
        times.append(elapsed)
    assert max(times) - min(times) < .06, times
    print("Frame deadlines preserve emulated speed with busy-wait, default, and long sleep caps: OK")


if __name__ == "__main__":
    test_keys()
    test_pixels()
    test_held_buttons()
    test_frame_pacing()
