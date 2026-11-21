//! Background transport only. The host owns RCore and drains requests on its command thread.
use anyhow::{Context, Result, bail, ensure};
use forwiroh::{Node, TransportMode, control::Command, pairing::Invitation, store::Policy};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    ffi::{CStr, CString, c_char},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

const MAX_BODY: usize = 1024 * 1024;
const MAX_PENDING: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

struct Pending {
    id: u64,
    request: Value,
    answer: oneshot::Sender<Value>,
    delivered: bool,
}

#[derive(Default)]
struct State {
    status: Value,
    invite: Value,
    results: VecDeque<Value>,
    events: VecDeque<Value>,
    pending: VecDeque<Pending>,
    token: String,
    remote_token: String,
    remote_port: u16,
    remote_tunnel: String,
}

struct Shared {
    state: Mutex<State>,
    sequence: AtomicU64,
    stop: CancellationToken,
    controls: mpsc::Sender<(u64, Value)>,
}

pub struct Handle {
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

fn bounded_push(queue: &mut VecDeque<Value>, value: Value) {
    if queue.len() == 32 {
        queue.pop_front();
    }
    queue.push_back(value);
}

fn outcome(result: Result<Value>) -> Value {
    match result {
        Ok(data) => json!({"data": data}),
        Err(e) => json!({"error": e.to_string()}),
    }
}

impl Shared {
    fn finish(&self, id: u64, result: Result<Value>) {
        bounded_push(
            &mut self.state.lock().unwrap().results,
            json!({"id":id,"reply":outcome(result)}),
        );
    }

    async fn core(&self, request: Value) -> Result<Value> {
        ensure!(!contains_nul(&request), "NUL in session request");
        ensure!(
            serde_json::to_vec(&request)?.len() <= MAX_BODY,
            "session request too large"
        );
        let (tx, rx) = oneshot::channel();
        {
            let mut state = self.state.lock().unwrap();
            state.pending.retain(|p| !p.answer.is_closed());
            ensure!(state.pending.len() < MAX_PENDING, "session queue full");
            state.pending.push_back(Pending {
                id: self.sequence.fetch_add(1, Ordering::Relaxed),
                request,
                answer: tx,
                delivered: false,
            });
        }
        tokio::select! {
            _ = self.stop.cancelled() => bail!("session stopped"),
            reply = timeout(IO_TIMEOUT, rx) => {
                let reply = reply.context("session busy: run r2fw poll or r2fw serve")??;
                if let Some(error) = reply["error"].as_str() { bail!("{error}"); }
                Ok(reply["data"].clone())
            }
        }
    }

    fn local(&self, request: Value) -> Result<Value> {
        let op = request["op"].as_str().context("missing op")?;
        let mut state = self.state.lock().unwrap();
        match op {
            "status" => Ok(json!({"transport": state.status, "invite": state.invite,
                "pending_commands": state.pending.iter().filter(|p| !p.answer.is_closed()).count(),
                "remote_port": state.remote_port, "results": state.results})),
            "events" => Ok(Value::Array(state.events.drain(..).collect())),
            "result" => {
                if let Some(id) = request["id"].as_u64() {
                    Ok(state
                        .results
                        .iter()
                        .find(|r| r["id"] == id)
                        .cloned()
                        .unwrap_or(json!({"pending": id})))
                } else {
                    Ok(state.results.back().cloned().unwrap_or(Value::Null))
                }
            }
            "next" => {
                let token = state.token.clone();
                state.pending.retain(|p| {
                    !p.answer.is_closed() && p.request.get("token").is_none_or(|t| t == &token)
                });
                Ok(match state.pending.iter_mut().find(|p| !p.delivered) {
                    Some(p) => {
                        p.delivered = true;
                        json!({"id": p.id, "request": p.request})
                    }
                    None => Value::Null,
                })
            }
            "reply" => {
                let id = request["id"].as_u64().context("missing id")?;
                if let Some(i) = state.pending.iter().position(|p| p.id == id) {
                    let p = state.pending.remove(i).unwrap();
                    let _ = p.answer.send(request["reply"].clone());
                }
                Ok(Value::Null)
            }
            "qr" => {
                let uri = state.invite["uri"]
                    .as_str()
                    .context("create an invitation first")?;
                let code = qrcode::QrCode::new(uri.as_bytes())?;
                Ok(
                    json!({"uri": uri, "qr": code.render::<qrcode::render::unicode::Dense1x2>()
                    .quiet_zone(true).build()}),
                )
            }
            _ => {
                let id = self.sequence.fetch_add(1, Ordering::Relaxed);
                drop(state);
                self.controls
                    .try_send((id, request))
                    .context("transport queue full or stopped")?;
                Ok(json!({"queued": id}))
            }
        }
    }
}

async fn control(shared: Arc<Shared>, node: Arc<Node>, job: Value) -> Result<Value> {
    let op = job["op"].as_str().context("missing op")?.to_owned();
    match op.as_str() {
        "invite" => {
            // Serialize rotation: changing the token also invalidates old HTTP URLs.
            let old = shared.state.lock().unwrap().invite["id"]
                .as_str()
                .map(str::to_owned);
            if let Some(id) = old {
                node.cancel_invitation(&id);
            }
            let invite = node.invitation()?;
            let uri = invite.uri()?;
            let mut state = shared.state.lock().unwrap();
            state.token = invite.secret;
            state.invite = json!({"uri": uri, "id": invite.id, "expires": invite.expires,
                "http_path": format!("/{}/", state.token)});
            Ok(state.invite.clone())
        }
        "cancel" => {
            let token = forwiroh::pairing::random()?;
            let mut state = shared.state.lock().unwrap();
            if let Some(id) = state.invite["id"].as_str() {
                node.cancel_invitation(id);
            }
            state.invite = Value::Null;
            state.token = token;
            Ok(Value::Null)
        }
        "connect" => {
            let uri = job["uri"].as_str().context("missing uri")?;
            let invite = Invitation::parse(uri)?;
            let id = node.pair(uri, "r2forwiroh").await?;
            shared.state.lock().unwrap().remote_token = invite.secret;
            Ok(json!({"peer": id}))
        }
        "open" => {
            let peer = job["peer"].as_str().context("missing peer")?;
            if let Some(token) = job["token"].as_str() {
                ensure!(valid_token(token), "invalid token");
            }
            ensure!(
                job["token"].as_str().is_some()
                    || valid_token(&shared.state.lock().unwrap().remote_token),
                "connect first or supply a token"
            );
            let port = job["port"].as_u64().unwrap_or(0);
            ensure!(port <= 65535, "invalid port");
            let id = node
                .forward(peer, format!("127.0.0.1:{port}").parse()?, "r2".into())
                .await?;
            let snapshot = node.snapshot();
            let detail = snapshot["tunnels"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["id"] == id)
                .and_then(|t| t["detail"].as_str())
                .context("missing tunnel")?;
            let local = detail
                .split_whitespace()
                .next()
                .context("missing local address")?;
            let port = local.parse::<std::net::SocketAddr>()?.port();
            let (old, url) = {
                let mut state = shared.state.lock().unwrap();
                if let Some(token) = job["token"].as_str() {
                    state.remote_token = token.to_owned();
                }
                state.remote_port = port;
                let old = std::mem::replace(&mut state.remote_tunnel, id.clone());
                (
                    old,
                    format!("http://127.0.0.1:{port}/{}/", state.remote_token),
                )
            };
            if !old.is_empty() {
                node.command(Command::ForwardStop { id: old }).await?;
            }
            Ok(json!({"id": id, "url":url}))
        }
        "close" => {
            let id = {
                let mut state = shared.state.lock().unwrap();
                state.remote_port = 0;
                std::mem::take(&mut state.remote_tunnel)
            };
            if !id.is_empty() {
                node.command(Command::ForwardStop { id }).await?;
            }
            Ok(Value::Null)
        }
        "cmd" | "ping" | "push" | "pull" => {
            let (port, token) = {
                let state = shared.state.lock().unwrap();
                (state.remote_port, state.remote_token.clone())
            };
            ensure!(
                port != 0 && valid_token(&token),
                "connect and open a peer first"
            );
            match op.as_str() {
                "cmd" => {
                    let command = job["command"].as_str().context("missing command")?;
                    let bytes = exchange(port, &token, "POST", "/cmd/", command.as_bytes()).await?;
                    Ok(json!({"output": String::from_utf8(bytes)?}))
                }
                "ping" => Ok(serde_json::from_slice(
                    &exchange(port, &token, "GET", "/health", &[]).await?,
                )?),
                "push" => {
                    let metadata = shared.core(json!({"op":"export"})).await?;
                    Ok(serde_json::from_slice(
                        &exchange(
                            port,
                            &token,
                            "POST",
                            "/sync",
                            &serde_json::to_vec(&metadata)?,
                        )
                        .await?,
                    )?)
                }
                _ => {
                    let bytes = exchange(port, &token, "GET", "/sync", &[]).await?;
                    shared.core(json!({"op":"import", "metadata": serde_json::from_slice::<Value>(&bytes)?})).await
                }
            }
        }
        _ => {
            let (_, command) = Command::parse(job, |id| node.tunnel_kind(id))?;
            node.command(command).await
        }
    }
}

fn valid_token(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

struct Http {
    first: String,
    body: Vec<u8>,
}

async fn read_http(stream: &mut TcpStream) -> Result<Http> {
    let mut stream = BufReader::new(stream);
    let mut bytes = Vec::new();
    let header_end = loop {
        ensure!(bytes.len() < 8192, "headers too large");
        let byte = stream.read_u8().await?;
        bytes.push(byte);
        if bytes.ends_with(b"\r\n\r\n") {
            break bytes.len();
        }
    };
    let header = std::str::from_utf8(&bytes[..header_end])?;
    let mut lines = header.split("\r\n");
    let first = lines.next().context("missing request line")?.to_owned();
    let mut length = None;
    for line in lines.filter(|s| !s.is_empty()) {
        let (name, value) = line.split_once(':').context("invalid header")?;
        ensure!(
            !name.eq_ignore_ascii_case("transfer-encoding"),
            "chunked bodies unsupported"
        );
        if name.eq_ignore_ascii_case("content-length") {
            ensure!(length.is_none(), "duplicate content-length");
            let n: usize = value.trim().parse()?;
            ensure!(n <= MAX_BODY, "body too large");
            length = Some(n);
        }
    }
    let mut body = vec![0; length.unwrap_or(0)];
    stream.read_exact(&mut body).await?;
    Ok(Http { first, body })
}

async fn exchange(
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<u8>> {
    ensure!(body.len() <= MAX_BODY, "body too large");
    timeout(IO_TIMEOUT, async {
        let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        let header = format!("{method} /{token}{path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(body).await?;
        let response = read_http(&mut stream).await?;
        ensure!(response.first.starts_with("HTTP/1.1 200 "), "remote: {}: {}", response.first, String::from_utf8_lossy(&response.body));
        Ok(response.body)
    }).await.context("remote request timed out")?
}

fn decode_command(path: &str) -> Result<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            ensure!(i + 2 < bytes.len(), "invalid percent escape");
            decoded.push(u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3])?,
                16,
            )?);
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    ensure!(!decoded.contains(&0), "NUL in command");
    Ok(String::from_utf8(decoded)?)
}

async fn handle_http(shared: Arc<Shared>, mut stream: TcpStream) -> Result<()> {
    let request = timeout(IO_TIMEOUT, read_http(&mut stream)).await??;
    let result = async {
        let parts: Vec<_> = request.first.split(' ').collect();
        ensure!(
            parts.len() == 3 && matches!(parts[2], "HTTP/1.1" | "HTTP/1.0"),
            "invalid HTTP request"
        );
        let (method, path) = (parts[0], parts[1]);
        let token = shared.state.lock().unwrap().token.clone();
        let prefix = format!("/{token}/");
        let path = path
            .strip_prefix(&prefix)
            .context("invalid or revoked session URL")?;
        let mut request = match (method, path) {
            ("GET", "health") => return Ok(serde_json::to_vec(
                &json!({"protocol":"r2fw/1", "transport":"reachable", "dispatch":"owner-thread"}))?),
            ("GET", "sync") => json!({"op":"export"}),
            ("POST", "sync") => json!({"op":"import", "metadata":serde_json::from_slice::<Value>(&request.body)?}),
            ("POST", "cmd/") => json!({"op":"cmd", "command":std::str::from_utf8(&request.body)?}),
            ("GET", path) if path.starts_with("cmd/") => json!({"op":"cmd", "command":decode_command(&path[4..])?}),
            _ => bail!("unknown method or endpoint"),
        };
        request["token"] = json!(token);
        let data = shared.core(request).await?;
        match data.as_str() {
            Some(output) => Ok(output.as_bytes().to_vec()),
            None => Ok(serde_json::to_vec(&data)?),
        }
    }
    .await;
    let (status, bytes) = match result {
        Ok(bytes) if bytes.len() <= MAX_BODY => ("200 OK", bytes),
        Ok(_) => ("413 Payload Too Large", b"response too large".to_vec()),
        Err(e) => (
            "400 Bad Request",
            serde_json::to_vec(&json!({"error": e.to_string()}))?,
        ),
    };
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
        bytes.len()
    );
    timeout(IO_TIMEOUT, async {
        stream.write_all(header.as_bytes()).await?;
        stream.write_all(&bytes).await
    })
    .await??;
    Ok(())
}

fn contains_nul(value: &Value) -> bool {
    match value {
        Value::String(s) => s.contains('\0'),
        Value::Array(a) => a.iter().any(contains_nul),
        Value::Object(o) => o.iter().any(|(k, v)| k.contains('\0') || contains_nul(v)),
        _ => false,
    }
}

async fn run(
    shared: Arc<Shared>,
    path: PathBuf,
    mut controls: mpsc::Receiver<(u64, Value)>,
    mode: TransportMode,
) -> Result<()> {
    let node = tokio::select! {
        _ = shared.stop.cancelled() => return Ok(()),
        node = Node::open(&path, "radare2", None, mode) => node?,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let policy = Policy {
        restricted: true,
        services: BTreeMap::from([("r2".into(), address.to_string())]),
        ..Policy::default()
    };
    node.set_pairing_policy(policy.clone())?;
    // Persisted peers must never retain an older, broader policy or a stale port.
    for peer in node.snapshot()["peers"].as_array().unwrap() {
        node.command(Command::PeerPolicy {
            peer: peer["id"].as_str().unwrap().into(),
            policy: policy.clone(),
        })
        .await?;
    }
    shared.state.lock().unwrap().token = forwiroh::pairing::random()?;
    let mut events = node.subscribe();
    let mut jobs = JoinSet::new();
    let mut clients = JoinSet::new();
    let mut tick = tokio::time::interval(Duration::from_millis(200));
    loop {
        tokio::select! {
            _ = shared.stop.cancelled() => break,
            _ = tick.tick() => {
                let mut snapshot = node.snapshot();
                snapshot["state"] = json!("running");
                snapshot["http_address"] = json!(address.to_string());
                shared.state.lock().unwrap().status = snapshot;
            }
            Some((id, job)) = controls.recv() => {
                let state = shared.clone();
                let n = node.clone();
                // Invitations are serialized in this loop to make link rotation atomic.
                if matches!(job["op"].as_str(), Some("invite" | "cancel" | "pair_cancel"
                    | "peer_approve" | "peer_revoke" | "peer_disconnect" | "peer_pending")) {
                    state.finish(id, control(state.clone(), n, job).await);
                } else if jobs.len() >= MAX_PENDING {
                    state.finish(id, Err(anyhow::anyhow!("too many running jobs")));
                } else {
                    jobs.spawn(async move {
                        state.finish(id, control(state.clone(), n, job).await);
                    });
                }
            }
            event = events.recv() => {
                if let Ok(event) = event { bounded_push(&mut shared.state.lock().unwrap().events, event); }
            }
            accepted = listener.accept(), if clients.len() < MAX_PENDING => {
                let (stream, _) = accepted?;
                clients.spawn(handle_http(shared.clone(), stream));
            }
            _ = jobs.join_next(), if !jobs.is_empty() => {},
            _ = clients.join_next(), if !clients.is_empty() => {},
        }
    }
    jobs.abort_all();
    clients.abort_all();
    while jobs.join_next().await.is_some() {}
    while clients.join_next().await.is_some() {}
    shared.state.lock().unwrap().pending.clear();
    node.shutdown().await;
    Ok(())
}

fn cstring(value: Value) -> *mut c_char {
    CString::new(value.to_string()).unwrap().into_raw()
}

fn command(args: &[&str]) -> Result<Value> {
    Ok(match args {
        ["status" | "statusj"] => json!({"op":"status"}),
        [op @ ("invite" | "cancel" | "qr" | "ping" | "events" | "close")] => json!({"op":op}),
        ["pending"] => json!({"op":"peer_pending"}),
        ["abort"] => json!({"op":"pair_cancel"}),
        ["network"] => json!({"op":"network_change"}),
        [op @ ("accept" | "reject"), id] => {
            json!({"op":"peer_approve", "id":id, "accept":*op == "accept"})
        }
        ["revoke", peer] => json!({"op":"peer_revoke", "peer":peer}),
        ["disconnect", peer] => json!({"op":"peer_disconnect", "peer":peer}),
        ["connect", uri] => json!({"op":"connect", "uri":uri}),
        ["open", peer, token @ ..] if token.len() <= 1 => {
            json!({"op":"open", "peer":peer, "token":token.first()})
        }
        ["cmd", text] => json!({"op":"cmd", "command":text}),
        ["sync", op @ ("push" | "pull")] => json!({"op":op}),
        ["result"] => json!({"op":"result"}),
        ["result", id] => json!({"op":"result", "id":id.parse::<u64>().context("invalid job id")?}),
        _ => bail!("Invalid arguments. Use r2fw?"),
    })
}

/// # Safety
/// `args` contains `argc` valid UTF-8 C strings; handle is live or NULL when stopped.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn r2fw_command(
    handle: *mut Handle,
    args: *const *const c_char,
    argc: usize,
) -> *mut c_char {
    let result = (|| {
        ensure!(!args.is_null() && argc <= 3, "invalid arguments");
        let args = unsafe { std::slice::from_raw_parts(args, argc) }
            .iter()
            .map(|arg| unsafe { CStr::from_ptr(*arg) }.to_str())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let request = command(&args)?;
        match unsafe { handle.as_ref() } {
            Some(handle) => handle.shared.local(request),
            None if request["op"] == "status" => Ok(json!({"transport":{"state":"stopped"},
                "invite":null,"pending_commands":0,"remote_port":0,"results":[]})),
            None => bail!("Run r2fw start first"),
        }
    })();
    cstring(outcome(result))
}

/// # Safety
/// `path` must be a valid UTF-8 C string. The returned handle belongs to the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn r2fw_new(path: *const c_char, local_only: bool) -> *mut Handle {
    if path.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(path) = unsafe { CStr::from_ptr(path) }.to_str() else {
        return std::ptr::null_mut();
    };
    let path = PathBuf::from(path);
    let (tx, rx) = mpsc::channel(MAX_PENDING);
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            status: json!({"state":"starting"}),
            ..State::default()
        }),
        sequence: AtomicU64::new(1),
        stop: CancellationToken::new(),
        controls: tx,
    });
    let state = shared.clone();
    let worker = std::thread::Builder::new()
        .name("r2forwiroh".into())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(anyhow::Error::from)
                .and_then(|runtime| {
                    let mode = if local_only {
                        TransportMode::LocalOnly
                    } else {
                        TransportMode::Automatic
                    };
                    runtime.block_on(run(state.clone(), path, rx, mode))
                });
            state.state.lock().unwrap().status = match result {
                Ok(()) => json!({"state":"stopped"}),
                Err(e) => json!({"state":"failed","error":e.to_string()}),
            };
        });
    match worker {
        Ok(worker) => Box::into_raw(Box::new(Handle {
            shared,
            worker: Some(worker),
        })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// Handle must be live and input a valid UTF-8 C string. Free replies with r2fw_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn r2fw_call(handle: *mut Handle, input: *const c_char) -> *mut c_char {
    let result = (|| {
        let handle = unsafe { handle.as_ref() }.context("no transport")?;
        ensure!(!input.is_null(), "missing request");
        let input = unsafe { CStr::from_ptr(input) }.to_str()?;
        ensure!(input.len() <= MAX_BODY, "request too large");
        handle.shared.local(serde_json::from_str(input)?)
    })();
    cstring(outcome(result))
}

/// # Safety
/// `text` must be NULL or a string returned by r2fw_call/r2fw_command.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn r2fw_string_free(text: *mut c_char) {
    if !text.is_null() {
        drop(unsafe { CString::from_raw(text) });
    }
}

/// # Safety
/// Caller must stop using handle before freeing it. Cancels I/O and joins every worker.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn r2fw_free(handle: *mut Handle) {
    if handle.is_null() {
        return;
    }
    let mut handle = unsafe { Box::from_raw(handle) };
    handle.shared.stop.cancel();
    if let Some(worker) = handle.worker.take() {
        let _ = worker.join();
    }
}
