#![cfg(feature = "stealth")]

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Spin up a minimal HTTP/1.1 server. The first connection receives a
/// `Accept-CH` response with the five high-entropy hint names; subsequent
/// connections receive a plain `200 OK`. All captured request header maps are
/// stored in the returned `Arc<Mutex<Vec<...>>>`.
async fn spawn_accept_ch_server() -> (u16, Arc<Mutex<Vec<HashMap<String, String>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured.clone();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    tokio::spawn(async move {
        loop {
            if let Ok((socket, _)) = listener.accept().await {
                let captured = captured_clone.clone();
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(handle_conn(socket, captured, n == 0));
            }
        }
    });

    (port, captured)
}

/// Spin up a plain HTTP/1.1 server that always responds `200 OK` with no
/// special headers, recording each request's headers.
async fn spawn_plain_server() -> (u16, Arc<Mutex<Vec<HashMap<String, String>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured: Arc<Mutex<Vec<HashMap<String, String>>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_clone = captured.clone();

    tokio::spawn(async move {
        loop {
            if let Ok((socket, _)) = listener.accept().await {
                let captured = captured_clone.clone();
                tokio::spawn(handle_conn(socket, captured, false));
            }
        }
    });

    (port, captured)
}

async fn handle_conn(
    socket: tokio::net::TcpStream,
    captured: Arc<Mutex<Vec<HashMap<String, String>>>>,
    send_accept_ch: bool,
) {
    let (read_half, mut write_half) = socket.into_split();
    let mut reader = BufReader::new(read_half);

    // Consume request line.
    let mut line = String::new();
    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
        return;
    }

    // Parse headers until blank line.
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let mut hdr = String::new();
        if reader.read_line(&mut hdr).await.unwrap_or(0) == 0 {
            break;
        }
        let trimmed = hdr.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(": ") {
            headers.insert(k.to_lowercase(), v.to_string());
        }
    }

    captured.lock().await.push(headers);

    if send_accept_ch {
        let _ = write_half
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Length: 0\r\n\
                  Accept-CH: sec-ch-ua-platform-version, sec-ch-ua-arch, \
                  sec-ch-ua-bitness, sec-ch-ua-full-version-list, sec-ch-ua-model\r\n\
                  Connection: close\r\n\r\n",
            )
            .await;
    } else {
        let _ = write_half
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
    }
}

// --- tests ---

/// After a server advertises Accept-CH on the first response, the client must
/// include all five high-entropy hints on the second request to the same origin.
#[tokio::test]
async fn high_entropy_hints_sent_after_accept_ch() {
    let (port, captured) = spawn_accept_ch_server().await;
    let url = url::Url::parse(&format!("http://127.0.0.1:{}/", port)).unwrap();

    let jar = Arc::new(obscura_net::CookieJar::new());
    let client = obscura_net::StealthHttpClient::new(jar);

    client.fetch(&url).await.unwrap();
    client.fetch(&url).await.unwrap();

    // Give server tasks time to flush captured headers.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let reqs = captured.lock().await;
    assert_eq!(reqs.len(), 2, "expected exactly 2 requests");

    let second = &reqs[1];
    for hint in &[
        "sec-ch-ua-platform-version",
        "sec-ch-ua-arch",
        "sec-ch-ua-bitness",
        "sec-ch-ua-full-version-list",
        "sec-ch-ua-model",
    ] {
        assert!(
            second.contains_key(*hint),
            "second request missing header: {}",
            hint
        );
    }

    assert_eq!(
        second.get("sec-ch-ua-platform-version").map(String::as_str),
        Some("\"6.8.0\""),
    );
    assert_eq!(
        second.get("sec-ch-ua-arch").map(String::as_str),
        Some("\"x86\""),
    );
    assert_eq!(
        second.get("sec-ch-ua-bitness").map(String::as_str),
        Some("\"64\""),
    );
    assert_eq!(
        second.get("sec-ch-ua-model").map(String::as_str),
        Some("\"\""),
    );
}

/// High-entropy hints must NOT be forwarded to a different origin even if a
/// previous request to another origin triggered Accept-CH. Chrome scopes
/// Accept-CH per-origin.
#[tokio::test]
async fn high_entropy_hints_not_sent_cross_origin() {
    let (port1, _captured1) = spawn_accept_ch_server().await;
    let (port2, captured2) = spawn_plain_server().await;

    let url1 = url::Url::parse(&format!("http://127.0.0.1:{}/", port1)).unwrap();
    let url2 = url::Url::parse(&format!("http://127.0.0.1:{}/", port2)).unwrap();

    let jar = Arc::new(obscura_net::CookieJar::new());
    let client = obscura_net::StealthHttpClient::new(jar);

    // Fetch from origin 1 — Accept-CH is advertised and cached.
    client.fetch(&url1).await.unwrap();
    // Fetch from origin 2 — different port, different origin.
    client.fetch(&url2).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let reqs2 = captured2.lock().await;
    assert_eq!(reqs2.len(), 1, "expected 1 request to origin 2");

    let req = &reqs2[0];
    for hint in &[
        "sec-ch-ua-platform-version",
        "sec-ch-ua-arch",
        "sec-ch-ua-bitness",
        "sec-ch-ua-full-version-list",
        "sec-ch-ua-model",
    ] {
        assert!(
            !req.contains_key(*hint),
            "high-entropy hint leaked cross-origin: {}",
            hint
        );
    }
}
