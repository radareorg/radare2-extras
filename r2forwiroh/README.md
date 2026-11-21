# r2forwiroh

Share the **current** radare2 session through
[forwiroh](https://github.com/trufae/forwiroh). The `r2fw` core plugin is both a
client and a server. Rust owns the background networking, pairing and HTTP;
a small C adapter uses `RCorePluginSession`, `.command` and `.call_ctx`.

Requires current radare2 with the command context API, Rust 1.95+, a C compiler
and pkg-config. The Forwiroh revision and Rust dependencies are pinned.

```sh
make
make install
# Or load explicitly, including on Windows: L /path/to/core_r2forwiroh.so
```

The Makefile targets Linux and macOS. Windows linking/packaging and physical
iOS/Android interoperability have not been validated.
Starting the external transport is disabled in r2 sandbox mode.

## Share a session

Inside r2, with your binary already open:

```text
r2fw start
r2fw statusj
r2fw invite
r2fw result
r2fw qr
```

`start` opens networking asynchronously. Wait for `transport.state` to become
`running`. Network operations return `{"data":{"queued":JOB_ID}}`; retrieve
their completion with `r2fw result JOB_ID`. A successful job has
`data.reply.data`; a failed job has `data.reply.error`. `result` without an ID
returns the most recent completion. Status includes the last 32 completions.
The queue retains up to 16 jobs and 16 core requests, with 30-second I/O and
core-response deadlines. Timed-out requests that have not started are discarded;
an already executing r2 command can still finish and change the session.

The invitation result contains a `forwiroh://pair?data=...` URL, its expiry and
`http_path`. Copy the URL or scan the QR with Forwiroh on your phone. On the host:

```text
r2fw pending
r2fw result
r2fw accept REQUEST_ID
r2fw result
r2fw serve
```

`reject REQUEST_ID` declines pairing. `serve` processes session requests until
Ctrl-C; networking continues afterwards. For interactive or GUI use, execute
`r2fw poll` regularly on the thread/queue that owns the r2 session instead.
An ordinary CLI prompt does not run that dispatcher while waiting for input.

In the phone's Forwiroh app, forward an available local port to the host's `r2`
service. Use `http://127.0.0.1:LOCAL_PORT` followed by `http_path` as the r2pipe
HTTP base URL. Keep the Forwiroh app/tunnel alive as required by the phone OS.
The QR establishes pairing; it does not automatically open a phone tunnel or
launch a separate r2 client application.

`invite` cancels the previous invitation and rotates the HTTP access path too.
Invitations expire after five minutes and can be redeemed once, with host
approval. `cancel` invalidates the current invitation and HTTP path. A paired
peer remains trusted until `revoke PEER_ID`, which also disconnects it. After
rotation, existing clients need the new HTTP token; already executing commands
are not rolled back. Treat invitation URLs and HTTP paths as credentials.

## Connect from another r2

```text
r2fw start /path/to/separate/client-identity
r2fw connect forwiroh://pair?data=...
# Accept on the other instance, then read the pairing result for PEER_ID.
r2fw result
r2fw open PEER_ID
r2fw result
r2fw ping
r2fw result
r2fw cmd "pd 10"
r2fw result
r2fw sync pull
r2fw poll
r2fw result
```

`open` allocates a loopback port and returns an HTTP base URL usable by other
r2pipe clients on this device. It obtains the token from the invitation used by
`connect`. After a restart or rotation, supply it explicitly with
`r2fw open PEER_ID TOKEN` (the component between slashes in `http_path`).
Opening another tunnel closes the previously selected one; `close` closes it
explicitly. `abort` cancels outgoing pairing, `disconnect PEER_ID` drops current
connections without forgetting trust, and `network` notifies Forwiroh after a
network-interface change. `ping` tests transport reachability; a remote command
also tests that the peer's core dispatcher is being serviced.
Use different state directories for simultaneous r2 instances: Forwiroh locks
each identity directory. Saved peers survive restarts; invitations, tokens,
tunnels, jobs and events do not. `r2fw stop` cancels requests and joins workers;
plugin unload does the same. `start STATE_DIR local` uses loopback connections
without Internet discovery or relays, useful for local testing.

## Metadata sync

`sync pull` merges remote annotations into this core; `sync push` sends this
core's annotations to the selected peer. Both cores must service `poll`/`serve`.
Version 1 transfers comments in the selected metadata space, and function
entrypoints and names. Incoming entries replace annotations at matching
addresses; unrelated entries remain. Deletions, basic blocks, cross-references,
types and automatic continuous synchronization are not part of this version.

The importer validates the whole schema and compares a SHA-256 of the current
IO descriptor and the binary load address before modifying annotations.
Addresses are hex strings, so JSON clients preserve all 64 bits. Data is applied
with the metadata/function APIs; it is never evaluated as an r2 script. Schema
or binary mismatches apply nothing. Allocation/name conflicts during application
return an error and may leave earlier entries applied. A sync hashes the complete
descriptor on the core thread; use finite file-backed descriptors for large work.
`sync export` prints the versioned metadata JSON locally for inspection.

## iaito integration contract

Load the plugin in the existing core. Send commands through iaito's serialized
core command queue, and schedule `r2fw poll` there approximately every 50–100 ms.
Do not run `serve` on the GUI thread. Polling executes at most 16 requests per
call; individual remote commands may take longer, like local analysis commands.
Query `r2fw statusj` for endpoint ID, peers, connection paths, tunnels,
pending-command count, current invitation and completed jobs. `events` drains
the last 32 pairing/connection events. This directory provides the plugin/API;
it does not add iaito widgets or a timer to the iaito repository.

The worker never accesses an `RCore`. The owner-thread dispatcher executes
commands with a cooperative task and a child console, keeping command contexts
and output separate. This deliberately avoids executing two commands against
shared analysis state from unrelated threads. Remote commands cannot invoke
the plugin's management commands recursively.

## Wire protocol and permissions

Forwiroh provides encrypted Iroh transport and explicit peer approval. Only the
named `r2` service at an ephemeral loopback port is authorized. Restored peers
also receive that restricted policy and the new service address at startup.
The HTTP access token changes at every start/invitation rotation.

| Endpoint relative to `http_path` | Method | Payload / response |
| --- | --- | --- |
| `health` | GET | JSON transport reachability (`r2fw/1`); does not need core dispatch |
| `cmd/COMMAND` | GET | Percent-encoded r2 command; plain command output (r2pipe) |
| `cmd/` | POST | UTF-8 r2 command body; plain command output |
| `sync` | GET | Versioned metadata JSON |
| `sync` | POST | Metadata JSON; imported comment/function counts |

HTTP accepts a maximum of 8 KiB of headers and 1 MiB per body/response, does not
follow redirects, and rejects ambiguous framing and embedded NULs. The service
has no browser CORS grants. Authorized clients have normal r2 command execution
privileges, including writes and shell commands; approve only trusted devices.
RAP is intentionally unnecessary here: r2pipe HTTP already covers commands and
JSON metadata without adding another binary protocol/parser.

## Tests

```sh
make test
python3 tests/test_plugin.py ./core_r2forwiroh.so
cargo clippy --all-targets --locked -- -D warnings
```

The Rust tests use actual local Forwiroh endpoints and tunnels, without relays.
The C tests cover typed metadata round trips, hostile comment text, hash mismatch,
64-bit addresses and malformed schemas. The Python test loads the plugin in two
r2 processes and exercises pairing, commands, both sync directions, restart and
shutdown with queued requests. Set `R2` to select a particular r2 executable.
