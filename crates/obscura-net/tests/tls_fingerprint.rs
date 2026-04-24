//! TLS fingerprint snapshot tests for obscura-net's stealth client.
//!
//! Two tests:
//!
//! - **`ja4_snapshot`** — binds a raw TCP server, fires an HTTPS request with
//!   the Chrome 145 wreq client, and reads the ClientHello before TLS is
//!   negotiated.  Derives the JA4 fingerprint and compares (or records) it
//!   against `tests/fixtures/chrome145_linux.ja4`.
//!
//! - **`h2_settings_snapshot`** — completes a TLS handshake with a local
//!   rustls server (self-signed cert, `danger_accept_invalid_certs`), reads
//!   the client's first HTTP/2 SETTINGS frame, and compares (or records) it
//!   against `tests/fixtures/chrome145_linux.h2settings.json`.
//!
//! # Generating / updating fixtures
//!
//! Run once on Linux with the stealth feature enabled:
//!
//! ```sh
//! UPDATE_TLS_FIXTURES=1 \
//!   cargo test -p obscura-net --features stealth --test tls_fingerprint
//! ```
//!
//! This records whatever `wreq` currently emits.  To establish a *real*
//! Chrome 145 Linux baseline, capture Chrome's ClientHello with Wireshark,
//! compute JA4 externally (e.g. with `ja4` CLI), then overwrite the fixture.
//! The fixture path is printed by the record run.
//!
//! JA4 spec: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
//! HTTP/2 SETTINGS spec: RFC 7540 §6.5

#![cfg(feature = "stealth")]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// ── Fixture helpers ───────────────────────────────────────────────────────────

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// If `UPDATE_TLS_FIXTURES=1` or the fixture file doesn't exist, write
/// `actual` to disk and return without asserting.  Otherwise compare.
fn record_or_compare(path: &PathBuf, actual: &str) {
    let update = std::env::var("UPDATE_TLS_FIXTURES").is_ok();
    if update || !path.exists() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, actual).unwrap();
        eprintln!("[tls_fingerprint] recorded {} → {}", path.display(), actual);
        return;
    }
    let expected = std::fs::read_to_string(path).unwrap();
    let expected = expected.trim();
    assert_eq!(
        actual,
        expected,
        "fingerprint drift in {}\n  current:  {}\n  expected: {}\n\
         To update: UPDATE_TLS_FIXTURES=1 cargo test -p obscura-net \
         --features stealth --test tls_fingerprint",
        path.display(),
        actual,
        expected,
    );
}

// ── JA4 parsing ───────────────────────────────────────────────────────────────

/// GREASE values (RFC 8701): both bytes equal, low nibble == 0xA.
fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) as u8;
    let lo = (v & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

fn sha256_prefix12(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
        .chars()
        .take(12)
        .collect()
}

/// Parse raw TLS record bytes containing a ClientHello and return the JA4
/// fingerprint string, or `None` if the bytes are not a parseable ClientHello.
fn compute_ja4(data: &[u8]) -> Option<String> {
    // TLS record: ContentType(1) + LegacyVersion(2) + Length(2)
    if data.len() < 9 || data[0] != 0x16 {
        return None;
    }
    // Handshake: Type(1) + Length(3) + ClientHello body
    let hs_start = 5;
    if data.len() <= hs_start || data[hs_start] != 0x01 {
        return None;
    }
    // Skip handshake type (1) + length (3)
    let mut pos = hs_start + 4;

    if pos + 2 > data.len() {
        return None;
    }
    let legacy_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2 + 32; // skip legacy_version + random[32]

    // session_id
    if pos >= data.len() {
        return None;
    }
    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;

    // cipher suites
    if pos + 2 > data.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cs_len > data.len() {
        return None;
    }
    let mut ciphers: Vec<u16> = Vec::new();
    for chunk in data[pos..pos + cs_len].chunks(2) {
        if chunk.len() == 2 {
            let c = u16::from_be_bytes([chunk[0], chunk[1]]);
            // exclude GREASE and TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)
            if !is_grease(c) && c != 0x00ff {
                ciphers.push(c);
            }
        }
    }
    pos += cs_len;

    // compression methods
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    // extensions
    if pos + 2 > data.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(data.len());

    let mut extensions: Vec<u16> = Vec::new();
    let mut supported_version: Option<u16> = None;
    let mut has_sni = false;
    let mut alpn_first: Option<String> = None;
    let mut sig_algs: Vec<u16> = Vec::new();

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > data.len() {
            break;
        }
        let ext_data = &data[pos..pos + ext_len];

        if !is_grease(ext_type) {
            extensions.push(ext_type);
        }

        match ext_type {
            // server_name
            0x0000 => {
                has_sni = ext_len > 0;
            }
            // signature_algorithms: list_len(2) + sig_alg(2)*
            0x000d => {
                if ext_data.len() >= 2 {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    let limit = (2 + list_len).min(ext_data.len());
                    let mut j = 2usize;
                    while j + 1 < limit {
                        sig_algs.push(u16::from_be_bytes([ext_data[j], ext_data[j + 1]]));
                        j += 2;
                    }
                }
            }
            // application_layer_protocol_negotiation: list_len(2) + proto_len(1) + proto
            0x0010 => {
                if ext_data.len() >= 4 {
                    let proto_len = ext_data[2] as usize;
                    if 3 + proto_len <= ext_data.len() {
                        if let Ok(s) = std::str::from_utf8(&ext_data[3..3 + proto_len]) {
                            alpn_first = Some(s.to_string());
                        }
                    }
                }
            }
            // supported_versions: vlist_len(1) + version(2)*
            0x002b => {
                if !ext_data.is_empty() {
                    let vlist_len = ext_data[0] as usize;
                    let limit = (1 + vlist_len).min(ext_data.len());
                    let mut j = 1usize;
                    while j + 1 < limit {
                        let v = u16::from_be_bytes([ext_data[j], ext_data[j + 1]]);
                        if !is_grease(v) && supported_version.is_none_or(|sv| v > sv) {
                            supported_version = Some(v);
                        }
                        j += 2;
                    }
                }
            }
            _ => {}
        }

        pos += ext_len;
    }

    let effective_ver = supported_version.unwrap_or(legacy_version);
    let ver_str = match effective_ver {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni_char = if has_sni { 'd' } else { 'i' };

    // JA4 ALPN: first and last character of the first ALPN protocol value.
    let alpn_str = match alpn_first.as_deref() {
        Some(p) if p.len() >= 2 => {
            let b = p.as_bytes();
            format!("{}{}", b[0] as char, b[b.len() - 1] as char)
        }
        Some(p) if !p.is_empty() => format!("{}0", p.as_bytes()[0] as char),
        _ => "00".to_string(),
    };

    let ja4_a = format!(
        "t{}{}{:02}{:02}{}",
        ver_str,
        sni_char,
        ciphers.len(),
        extensions.len(),
        alpn_str
    );

    let mut sorted_ciphers = ciphers;
    sorted_ciphers.sort_unstable();
    let cipher_str = sorted_ciphers
        .iter()
        .map(|c| format!("{:04x}", c))
        .collect::<Vec<_>>()
        .join(",");

    let mut sorted_sas = sig_algs;
    sorted_sas.sort_unstable();
    let sa_str = sorted_sas
        .iter()
        .map(|sa| format!("{:04x}", sa))
        .collect::<Vec<_>>()
        .join(",");

    Some(format!(
        "{}_{}_{}",
        ja4_a,
        sha256_prefix12(&cipher_str),
        sha256_prefix12(&sa_str),
    ))
}

// ── wreq client builder ───────────────────────────────────────────────────────

/// Build a Chrome 145 Linux wreq client.  If `extra_cert` is provided, it is
/// added to the cert store (needed for the H2 test's self-signed server).
fn build_wreq_client(extra_cert: Option<&[u8]>) -> wreq::Client {
    let emulation = wreq_util::EmulationOption::builder()
        .emulation(wreq_util::Emulation::Chrome145)
        .emulation_os(wreq_util::EmulationOS::Linux)
        .build();
    let mut cs_builder = wreq::tls::CertStore::builder().set_default_paths();
    if let Some(der) = extra_cert {
        cs_builder = cs_builder.add_der_cert(der);
    }
    let cert_store = cs_builder.build().expect("cert store");
    wreq::Client::builder()
        .emulation(emulation)
        .cert_store(cert_store)
        .timeout(Duration::from_secs(5))
        .redirect(wreq::redirect::Policy::none())
        .build()
        .expect("failed to build test wreq client")
}

// ── TLS server builder ────────────────────────────────────────────────────────

/// Returns a TLS acceptor and the DER-encoded CA certificate for the client.
fn build_tls_acceptor() -> (TlsAcceptor, Vec<u8>) {
    let cert = generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
        .expect("rcgen cert generation failed");

    let cert_der_bytes = cert.serialize_der().expect("serialize cert DER");
    let rustls_cert = CertificateDer::from(cert_der_bytes.clone());
    let key_der = PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![rustls_cert], key_der.into())
        .expect("invalid cert/key");
    // Advertise h2 so wreq negotiates HTTP/2.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    (TlsAcceptor::from(Arc::new(config)), cert_der_bytes)
}

// ── HTTP/2 SETTINGS helpers ───────────────────────────────────────────────────

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Parse an HTTP/2 SETTINGS frame payload into a stable ordered map of
/// `name → value` pairs.
fn parse_h2_settings(payload: &[u8]) -> BTreeMap<String, u32> {
    let mut map = BTreeMap::new();
    for chunk in payload.chunks(6) {
        if chunk.len() < 6 {
            break;
        }
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
        let name = match id {
            1 => "HEADER_TABLE_SIZE".to_string(),
            2 => "ENABLE_PUSH".to_string(),
            3 => "MAX_CONCURRENT_STREAMS".to_string(),
            4 => "INITIAL_WINDOW_SIZE".to_string(),
            5 => "MAX_FRAME_SIZE".to_string(),
            6 => "MAX_HEADER_LIST_SIZE".to_string(),
            8 => "ENABLE_CONNECT_PROTOCOL".to_string(),
            _ => format!("SETTINGS_{:04x}", id),
        };
        map.insert(name, val);
    }
    map
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Captures the TLS ClientHello sent by the Chrome 145 wreq client and derives
/// the JA4 fingerprint.  Compares against (or records to) the fixture file.
#[tokio::test]
async fn ja4_snapshot() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().unwrap().port();

    // Accept one connection, read the raw ClientHello (first TLS record), close.
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        buf.truncate(n);
        buf
    });

    // No special cert needed — the server closes before cert validation.
    let client = build_wreq_client(None);
    // Ignore the error — server closes immediately after reading.
    let _ = client
        .get(format!("https://127.0.0.1:{}", port))
        .send()
        .await;

    let raw = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task timed out")
        .expect("server task panicked");

    let ja4 = compute_ja4(&raw).unwrap_or_else(|| "PARSE_ERROR".to_string());
    record_or_compare(&fixture_path("chrome145_linux.ja4"), &ja4);
}

/// Completes a TLS handshake with a local rustls server, reads the client's
/// HTTP/2 connection preface and first SETTINGS frame, then compares (or
/// records) the settings against the fixture file.
#[tokio::test]
async fn h2_settings_snapshot() {
    let (acceptor, cert_der) = build_tls_acceptor();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().unwrap().port();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(tcp).await.expect("TLS handshake");

        // HTTP/2 connection preface: 24-byte magic string.
        let mut preface = vec![0u8; H2_PREFACE.len()];
        tls.read_exact(&mut preface).await.expect("read H2 preface");
        assert_eq!(
            preface.as_slice(),
            H2_PREFACE,
            "unexpected HTTP/2 connection preface"
        );

        // HTTP/2 frame header: Length(3) + Type(1) + Flags(1) + StreamID(4)
        let mut frame_hdr = [0u8; 9];
        tls.read_exact(&mut frame_hdr)
            .await
            .expect("read H2 frame header");
        let payload_len = (u32::from(frame_hdr[0]) << 16
            | u32::from(frame_hdr[1]) << 8
            | u32::from(frame_hdr[2])) as usize;
        let frame_type = frame_hdr[3];
        assert_eq!(
            frame_type, 0x4,
            "expected SETTINGS frame (type 0x4), got {:#x}",
            frame_type
        );

        let mut payload = vec![0u8; payload_len];
        tls.read_exact(&mut payload)
            .await
            .expect("read H2 SETTINGS payload");

        // Send empty SETTINGS then SETTINGS_ACK so the client doesn't stall.
        // SETTINGS frame: length=0, type=0x4, flags=0x0, stream=0
        let _ = tls.write_all(&[0u8, 0, 0, 0x04, 0x00, 0, 0, 0, 0]).await;
        // SETTINGS ACK: length=0, type=0x4, flags=0x1, stream=0
        let _ = tls.write_all(&[0u8, 0, 0, 0x04, 0x01, 0, 0, 0, 0]).await;

        payload
    });

    let client = build_wreq_client(Some(&cert_der));
    // Ignore the error — server sends no HTTP response.
    let _ = client
        .get(format!("https://127.0.0.1:{}", port))
        .send()
        .await;

    let settings_payload = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server task timed out")
        .expect("server task panicked");

    let settings = parse_h2_settings(&settings_payload);
    let json = serde_json::to_string_pretty(&settings).expect("serialize settings");
    record_or_compare(&fixture_path("chrome145_linux.h2settings.json"), &json);
}
