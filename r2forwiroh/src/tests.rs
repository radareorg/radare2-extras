use super::*;

fn shared() -> (Arc<Shared>, mpsc::Receiver<Value>) {
    let (controls, rx) = mpsc::channel(MAX_PENDING);
    (
        Arc::new(Shared {
            state: Mutex::new(State::default()),
            sequence: AtomicU64::new(1),
            stop: CancellationToken::new(),
            controls,
        }),
        rx,
    )
}

async fn wait_for(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(10), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("condition timed out");
}

async fn job(shared: &Shared, request: Value) -> Value {
    let id = shared.local(request).unwrap()["queued"].as_u64().unwrap();
    wait_for(|| {
        shared
            .state
            .lock()
            .unwrap()
            .results
            .iter()
            .any(|r| r["id"] == id)
    })
    .await;
    shared
        .state
        .lock()
        .unwrap()
        .results
        .iter()
        .find(|r| r["id"] == id)
        .unwrap()["reply"]
        .clone()
}

async fn request(bytes: &[u8]) -> Result<Http> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut client = TcpStream::connect(listener.local_addr()?).await?;
    let (mut server, _) = listener.accept().await?;
    client.write_all(bytes).await?;
    client.shutdown().await?;
    read_http(&mut server).await
}

#[tokio::test]
async fn http_framing_rejects_ambiguous_or_unbounded_input() {
    for header in [
        "Content-Length: 1048577\r\n",
        "Content-Length: -1\r\n",
        "Content-Length: 1\r\nContent-Length: 1\r\n",
        "Transfer-Encoding: chunked\r\n",
    ] {
        let input = format!("POST / HTTP/1.1\r\n{header}\r\nx");
        assert!(request(input.as_bytes()).await.is_err(), "{header}");
    }
    assert!(
        request(b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\nx")
            .await
            .is_err()
    );
    let result = request(b"POST / HTTP/1.1\r\ncontent-length: 3\r\n\r\n\nxy")
        .await
        .unwrap();
    assert_eq!(result.body, b"\nxy");
}

#[test]
fn command_decoding_is_strict_and_preserves_plus() {
    assert_eq!(decode_command("?v%208%2B1").unwrap(), "?v 8+1");
    assert_eq!(decode_command("+1").unwrap(), "+1");
    for input in ["%", "%0", "%zz", "%00", "%ff"] {
        assert!(decode_command(input).is_err());
    }
    assert!(contains_nul(&json!({"comments":[{"text":"x\0y"}]})));
    assert!(contains_nul(&json!({"x\0y":1})));
    assert!(!contains_nul(
        &json!({"text":"`;!touch /tmp/not-a-command"})
    ));
}

#[tokio::test]
async fn queue_is_bounded_and_expired_or_revoked_requests_never_dispatch() {
    let (state, _rx) = shared();
    state.state.lock().unwrap().token = "current".into();
    let s = state.clone();
    let pending = tokio::spawn(async move { s.core(json!({"op":"cmd","token":"old"})).await });
    wait_for(|| !state.state.lock().unwrap().pending.is_empty()).await;
    assert!(state.local(json!({"op":"next"})).unwrap().is_null());
    assert!(pending.await.unwrap().is_err());
    let mut tasks = Vec::new();
    for _ in 0..MAX_PENDING {
        let s = state.clone();
        tasks.push(tokio::spawn(
            async move { s.core(json!({"op":"cmd"})).await },
        ));
    }
    wait_for(|| state.state.lock().unwrap().pending.len() == MAX_PENDING).await;
    assert!(
        state
            .core(json!({"op":"cmd"}))
            .await
            .unwrap_err()
            .to_string()
            .contains("full")
    );
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    assert!(state.local(json!({"op":"next"})).unwrap().is_null());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_commands_rotation_revocation_and_shutdown_over_real_tunnel() {
    let home = tempfile::tempdir().unwrap();
    let phone = tempfile::tempdir().unwrap();
    let (server, server_rx) = shared();
    let (client, client_rx) = shared();
    let server_task = tokio::spawn(run(
        server.clone(),
        home.path().into(),
        server_rx,
        TransportMode::LocalOnly,
    ));
    let client_task = tokio::spawn(run(
        client.clone(),
        phone.path().into(),
        client_rx,
        TransportMode::LocalOnly,
    ));
    wait_for(|| {
        server.state.lock().unwrap().status["state"] == "running"
            && client.state.lock().unwrap().status["state"] == "running"
    })
    .await;
    let first = job(&server, json!({"op":"invite"})).await;
    let uri = first["data"]["uri"].as_str().unwrap().to_owned();
    let invite = Invitation::parse(&uri).unwrap();
    assert_eq!(server.local(json!({"op":"qr"})).unwrap()["uri"], uri);
    let pairing = {
        let c = client.clone();
        tokio::spawn(async move { job(&c, json!({"op":"connect","uri":uri})).await })
    };
    let mut pending = Value::Null;
    for _ in 0..100 {
        pending = job(&server, json!({"op":"peer_pending"})).await;
        if pending["data"].as_array().is_some_and(|a| !a.is_empty()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let id = pending["data"][0]["id"].as_str().unwrap();
    let server_peer = pending["data"][0]["peer"].clone();
    assert!(
        job(&server, json!({"op":"peer_approve","id":id,"accept":true}))
            .await
            .get("error")
            .is_none()
    );
    let paired = pairing.await.unwrap();
    let peer = paired["data"]["peer"].as_str().unwrap();
    let opened = job(&client, json!({"op":"open","peer":peer})).await;
    assert!(
        opened["data"]["url"]
            .as_str()
            .unwrap()
            .contains(&invite.secret)
    );
    let health = job(&client, json!({"op":"ping"})).await;
    assert_eq!(health["data"]["protocol"], "r2fw/1");
    let remote_command = {
        let c = client.clone();
        tokio::spawn(async move { job(&c, json!({"op":"cmd","command":"?v 8+1"})).await })
    };
    wait_for(|| !server.state.lock().unwrap().pending.is_empty()).await;
    let next = server.local(json!({"op":"next"})).unwrap();
    assert_eq!(next["request"]["command"], "?v 8+1");
    server
        .local(json!({"op":"reply","id":next["id"],"reply":{"data":"9\n"}}))
        .unwrap();
    assert_eq!(remote_command.await.unwrap()["data"]["output"], "9\n");
    let port = client.state.lock().unwrap().remote_port;
    // A new invitation invalidates both the old pairing capability and old HTTP URLs.
    let second = job(&server, json!({"op":"invite"})).await;
    assert_ne!(second["data"]["uri"], first["data"]["uri"]);
    assert!(
        exchange(port, &invite.secret, "GET", "/health", &[])
            .await
            .is_err()
    );
    assert!(
        job(&server, json!({"op":"peer_revoke","peer":server_peer}))
            .await
            .get("error")
            .is_none()
    );
    assert!(
        exchange(port, &invite.secret, "GET", "/health", &[])
            .await
            .is_err()
    );
    server.stop.cancel();
    client.stop.cancel();
    timeout(Duration::from_secs(10), server_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), client_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn canceled_invite_rejects_pairing_and_invalid_token_never_reaches_core() {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(directory.path(), "test", None, TransportMode::LocalOnly)
        .await
        .unwrap();
    let (state, _rx) = shared();
    let invited = control(state.clone(), node.clone(), json!({"op":"invite"}))
        .await
        .unwrap();
    let uri = invited["uri"].as_str().unwrap().to_owned();
    let token = state.state.lock().unwrap().token.clone();
    control(state.clone(), node.clone(), json!({"op":"cancel"}))
        .await
        .unwrap();
    assert_ne!(state.state.lock().unwrap().token, token);
    assert!(state.local(json!({"op":"qr"})).is_err());
    assert!(state.local(json!({"op":"next"})).unwrap().is_null());
    let client_dir = tempfile::tempdir().unwrap();
    let client = Node::open(client_dir.path(), "client", None, TransportMode::LocalOnly)
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_secs(5), client.pair(&uri, "test"))
            .await
            .unwrap()
            .is_err()
    );
    assert!(node.pending().as_array().unwrap().is_empty());
    let mut expired = Invitation::parse(&uri).unwrap();
    expired.expires = forwiroh::pairing::now() - 1;
    assert!(Invitation::parse(&expired.uri().unwrap()).is_err());
    // Denial must not establish trust or leave a pending pairing behind.
    let new = node.invitation().unwrap().uri().unwrap();
    let c = client.clone();
    let pairing = tokio::spawn(async move { c.pair(&new, "test").await });
    wait_for(|| !node.pending().as_array().unwrap().is_empty()).await;
    let id = node.pending()[0]["id"].as_str().unwrap().to_owned();
    node.approve(&id, false).unwrap();
    assert!(pairing.await.unwrap().is_err());
    assert!(node.snapshot()["peers"].as_array().unwrap().is_empty());
    client.shutdown().await;
    node.shutdown().await;
}

#[tokio::test]
async fn bad_http_capabilities_and_nuls_never_enter_the_core_queue() {
    let (state, _rx) = shared();
    let token = forwiroh::pairing::random().unwrap();
    state.state.lock().unwrap().token = token.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let s = state.clone();
    let server = tokio::spawn(async move {
        for _ in 0..4 {
            let (stream, _) = listener.accept().await.unwrap();
            handle_http(s.clone(), stream).await.unwrap();
        }
    });
    assert!(
        exchange(port, &"X".repeat(43), "GET", "/health", &[])
            .await
            .is_err()
    );
    assert!(
        exchange(port, &token, "POST", "/cmd/", b"?vi 1\0;!id")
            .await
            .is_err()
    );
    assert!(
        exchange(
            port,
            &token,
            "POST",
            "/sync",
            br#"{"comments":[{"text":"x\u0000y"}]}"#
        )
        .await
        .is_err()
    );
    assert!(
        exchange(port, &token, "GET", "/cmd/%00", &[])
            .await
            .is_err()
    );
    server.await.unwrap();
    assert!(state.state.lock().unwrap().pending.is_empty());
}
