#!/usr/bin/env python3
"""Two real r2 sessions, a real Forwiroh tunnel, and typed metadata round trips."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time


class R2:
    def __init__(self, plugin):
        self.process = subprocess.Popen(
            [os.environ.get("R2", "r2"), "-N", "-q0", "malloc://256"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        self.read()
        self.cmd("e scr.color=0")
        self.cmd("L " + str(plugin))
        assert "r2fw start" in self.cmd("r2fw?")

    def read(self):
        output = bytearray()
        while True:
            if not select.select([self.process.stdout], [], [], 40)[0]:
                raise TimeoutError("r2 command timed out")
            byte = os.read(self.process.stdout.fileno(), 1)
            if byte == b"\0":
                return output.decode()
            if not byte:
                raise RuntimeError(f"r2 exited: {self.process.poll()}")
            output.extend(byte)

    def cmd(self, command):
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()
        return self.read()

    def query(self, command):
        return json.loads(self.cmd(command))

    def close(self):
        try:
            self.cmd("r2fw stop")
            self.process.stdin.write(b"q!\n")
            self.process.stdin.flush()
            self.process.wait(timeout=10)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()
            self.process.stdin.close()
            self.process.stdout.close()


def wait_for(predicate):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise TimeoutError("condition did not become true")


def main():
    plugin = Path(sys.argv[1] if len(sys.argv) > 1 else "core_r2forwiroh.so").resolve()
    server, client = R2(plugin), R2(plugin)
    sessions = (server, client)

    def pump():
        for r2 in sessions:
            r2.cmd("r2fw poll")

    def result(r2, job):
        def check():
            pump()
            reply = r2.query(f"r2fw result {job}")["data"]
            if "reply" in reply:
                assert "error" not in reply["reply"], reply
                return {"value": reply["reply"]["data"]}
        return wait_for(check)["value"]

    def run(r2, command):
        return result(r2, r2.query("r2fw " + command)["data"]["queued"])

    try:
        with tempfile.TemporaryDirectory() as directory:
            for index, r2 in enumerate(sessions):
                r2.cmd(f"r2fw start {directory}/{index} local")
                wait_for(lambda: r2.query("r2fw statusj")["data"]["transport"].get("state") == "running")
            server.cmd("CC hello")
            server.cmd("af+ 64 sample")
            invite = run(server, "invite")
            pair = client.query("r2fw connect " + invite["uri"])["data"]["queued"]
            pending = wait_for(lambda: run(server, "pending"))
            run(server, "accept " + pending[0]["id"])
            peer = result(client, pair)["peer"]
            opened = run(client, "open " + peer)
            assert opened["url"].startswith("http://127.0.0.1:")
            assert run(client, "ping")["protocol"] == "r2fw/1"
            output = run(client, 'cmd "?vi 8+1"')["output"]
            assert output.strip() == "9", repr(output)
            assert client.cmd("?vi 3+1").strip() == "4", "remote console leaked into local console"
            run(client, "sync pull")
            assert "hello" in client.cmd("CC.")
            assert "sample" in client.cmd("aflj")
            client.cmd("CC client comment")
            run(client, "sync push")
            assert "client comment" in server.cmd("CC.")
            # The CLI service loop executes requests while the pipe is otherwise idle.
            server.process.stdin.write(b"r2fw serve\n")
            server.process.stdin.flush()
            try:
                served_job = client.query('r2fw cmd "?vi 21*2"')["data"]["queued"]
                def served():
                    client.cmd("r2fw poll")
                    data = client.query(f"r2fw result {served_job}")["data"]
                    return data.get("reply")
                assert wait_for(served)["data"]["output"].strip() == "42"
            finally:
                server.process.send_signal(signal.SIGINT)
                server.read()
            # A different binary must fail before modifying metadata.
            client.cmd("wx 01 @ 0")
            job = client.query("r2fw sync push")["data"]["queued"]
            def rejected():
                pump()
                data = client.query(f"r2fw result {job}")["data"]
                return data.get("reply")
            assert "Binary hash" in wait_for(rejected)["error"]
            old = invite["uri"]
            rotated = run(server, "invite")
            assert rotated["uri"] != old
            run(client, "open " + peer + " " + rotated["http_path"].strip("/"))
            assert "error" not in server.query("r2fw statusj")
            # Shutdown while requests are queued must not wait for the core dispatcher.
            client.query('r2fw cmd "?v 1"')
            wait_for(lambda: server.query("r2fw statusj")["data"]["pending_commands"] > 0)
            server.cmd("r2fw stop")
            server.cmd(f"r2fw start {directory}/0 local")
            wait_for(lambda: server.query("r2fw statusj")["data"]["transport"].get("state") == "running")
            assert server.query("r2fw statusj")["data"]["transport"]["peers"], "trusted peer was not persisted"
            print("plugin integration tests passed")
    finally:
        for r2 in sessions:
            r2.close()


if __name__ == "__main__":
    main()
