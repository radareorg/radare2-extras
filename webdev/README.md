# webdev

A native radare2 core plugin (in C) that exposes the **current r2 session** to
the **Chrome DevTools Protocol** (CDP). Point a Chromium-based DevTools frontend
at it and you get a live JavaScript REPL — running through r2's embedded QuickJS
(`r2js`) — in the DevTools **Console**, with full access to the session:
the open file, maps, functions, and any resource reachable from r2.

```
webdev [port]
```

## Build & install

```sh
make            # build core_webdev.$(R2_LIBEXT)
make install    # copy into the r2 user plugin dir (+ codesign on macOS)
```

Requires `pkg-config --exists r_core` (a radare2 dev install).

## Usage

Inside r2, start the server (it blocks the prompt, like `=h`; press `^C` to stop):

```
[0x00000000]> webdev
[webdev] serving r2 session on http://127.0.0.1:9229
[webdev] open chrome://inspect, add 127.0.0.1:9229 as a target
[webdev] press ^C to stop
```

or pick a port: `webdev 9333`. Each r2 instance you want to inspect runs its own
server on its own port.

Then, in **Chrome / Edge / Brave**:

1. Open `chrome://inspect`.
2. Click **Configure…** and add `127.0.0.1:9229` (and any other ports you used).
3. Your r2 session shows up under **Remote Target** — the title is the open
   filename. Click **inspect**.
4. Use the DevTools **Console** to run r2js one-liners:

```js
r2.cmd("ij")                 // file info
r2.cmd("o")                  // list open files / resources
r2.cmd("afl")                // functions
r2.cmdj("ij").core.file      // structured JSON access
r2.cmd("px 64")              // hexdump
r2.cmd("s entry0; pd 10")    // seek + disassemble
```

Anything you can type at the r2 prompt is available via `r2.cmd()` /
`r2.cmdj()`, and the returned value / any `console.log` output is shown in the
Console.

## Discovery endpoints (plain HTTP)

- `GET /json/version` — browser identity + protocol version
- `GET /json` · `/json/list` — this session as a single CDP target
- `GET /` — a human-readable landing page with session info and instructions

## How it works

- A blocking accept loop serves the CDP discovery over HTTP and upgrades
  DevTools' `GET` to a **WebSocket** (handshake via SHA1 + base64, framing
  implemented over `RSocket`).
- CDP `Runtime.enable` announces one execution context; `Runtime.evaluate`
  wraps the expression, base64-encodes it, and runs it as `js base64:…` so r2's
  command parser never mangles the source. Console output is captured and
  returned as the result. Other CDP methods are stubbed to keep DevTools happy.
- It runs single-threaded in the foreground, so r2 core access is safe (no
  concurrent access from a background thread).

## Caveats

- **Safari's Develop menu won't discover this.** Apple's remote inspection uses
  the WebKit Remote Web Inspector protocol (registered with `webinspectord`),
  which is *not* CDP. Use a Chromium-based DevTools frontend.
- The server blocks the r2 prompt while running (drive the session from the
  DevTools Console instead). `^C` returns to the prompt.
- Bind is local (`127.0.0.1`); expose beyond localhost at your own risk — the
  Console gives full command execution over the session.
