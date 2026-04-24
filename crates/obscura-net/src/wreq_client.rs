#[cfg(feature = "stealth")]
use std::collections::{HashMap, HashSet};
#[cfg(feature = "stealth")]
use std::error::Error;
#[cfg(feature = "stealth")]
use std::sync::{Arc, OnceLock};
#[cfg(feature = "stealth")]
use std::time::Duration;

#[cfg(feature = "stealth")]
use tokio::sync::RwLock;
#[cfg(feature = "stealth")]
use url::Url;

#[cfg(feature = "stealth")]
use crate::client::{ObscuraNetError, Response};
#[cfg(feature = "stealth")]
use crate::cookies::CookieJar;

#[cfg(feature = "stealth")]
pub const STEALTH_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36";

#[cfg(feature = "stealth")]
static CLIENT_HINTS: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Returns the map of all supported UA-CH header name → header value,
/// loaded once from `data/client_hints.json` at first call.
#[cfg(feature = "stealth")]
fn client_hints() -> &'static HashMap<String, String> {
    CLIENT_HINTS.get_or_init(|| {
        serde_json::from_str(include_str!("../data/client_hints.json"))
            .expect("client_hints.json is valid JSON")
    })
}

/// Derive the origin key (scheme + host + explicit port) used to scope the
/// Accept-CH cache, matching Chrome's per-origin semantics.
#[cfg(feature = "stealth")]
fn url_origin(url: &Url) -> String {
    match url.port() {
        Some(port) => format!("{}://{}:{}", url.scheme(), url.host_str().unwrap_or(""), port),
        None => format!("{}://{}", url.scheme(), url.host_str().unwrap_or("")),
    }
}

#[cfg(feature = "stealth")]
pub struct StealthHttpClient {
    client: wreq::Client,
    pub cookie_jar: Arc<CookieJar>,
    pub extra_headers: RwLock<HashMap<String, String>>,
    pub in_flight: Arc<std::sync::atomic::AtomicU32>,
    /// Per-origin set of hint names declared via `Accept-CH`. Only hints whose
    /// names appear in `client_hints.json` are ever injected.
    accept_ch_cache: RwLock<HashMap<String, HashSet<String>>>,
}

#[cfg(feature = "stealth")]
impl StealthHttpClient {
    pub fn new(cookie_jar: Arc<CookieJar>) -> Self {
        Self::with_proxy(cookie_jar, None)
    }

    pub fn with_proxy(cookie_jar: Arc<CookieJar>, proxy_url: Option<&str>) -> Self {
        let cert_store = wreq::tls::CertStore::builder()
            .set_default_paths()
            .build()
            .expect("Failed to load system CA certificates");

        let emulation_opts = wreq_util::EmulationOption::builder()
            .emulation(wreq_util::Emulation::Chrome145)
            .emulation_os(wreq_util::EmulationOS::Linux)
            .build();

        let mut builder = wreq::Client::builder()
            .emulation(emulation_opts)
            .cert_store(cert_store)
            .timeout(Duration::from_secs(30))
            .redirect(wreq::redirect::Policy::none());

        if let Some(proxy) = proxy_url {
            if let Ok(p) = wreq::Proxy::all(proxy) {
                builder = builder.proxy(p);
            }
        }

        let client = builder
            .build()
            .expect("failed to build wreq stealth client");

        StealthHttpClient {
            client,
            cookie_jar,
            extra_headers: RwLock::new(HashMap::new()),
            in_flight: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            accept_ch_cache: RwLock::new(HashMap::new()),
        }
    }

    pub async fn fetch(&self, url: &Url) -> Result<Response, ObscuraNetError> {
        let mut current_url = url.clone();
        let mut redirects = Vec::new();

        for _ in 0..20 {
            let mut req = self.client.get(current_url.as_str());

            let cookie_header = self.cookie_jar.get_cookie_header(&current_url);
            if !cookie_header.is_empty() {
                req = req.header("Cookie", &cookie_header);
            }

            for (k, v) in self.extra_headers.read().await.iter() {
                req = req.header(k.as_str(), v.as_str());
            }

            // Inject high-entropy hints declared by this origin via Accept-CH.
            // Collect into a Vec first to release the read-lock before sending.
            let origin_key = url_origin(&current_url);
            let hints_to_add: Vec<(String, String)> = {
                let cache = self.accept_ch_cache.read().await;
                match cache.get(&origin_key) {
                    Some(hint_names) => {
                        let all = client_hints();
                        hint_names
                            .iter()
                            .filter_map(|name| all.get(name).map(|v| (name.clone(), v.clone())))
                            .collect()
                    }
                    None => Vec::new(),
                }
            };
            for (name, val) in &hints_to_add {
                req = req.header(name.as_str(), val.as_str());
            }

            self.in_flight
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let resp = req.send().await.map_err(|e| {
                self.in_flight
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                ObscuraNetError::Network(format!(
                    "{}: {} (source: {:?})",
                    current_url,
                    e,
                    e.source()
                ))
            })?;
            self.in_flight
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

            let status = resp.status();

            for val in resp.headers().get_all("set-cookie") {
                if let Ok(s) = val.to_str() {
                    self.cookie_jar.set_cookie(s, &current_url);
                }
            }

            let response_headers: HashMap<String, String> = resp
                .headers()
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_lowercase(),
                        v.to_str().unwrap_or("").to_string(),
                    )
                })
                .collect();

            // Update Accept-CH cache: union the advertised hints into the
            // per-origin set so they are injected on the next same-origin request.
            if let Some(accept_ch_val) = response_headers.get("accept-ch") {
                let hints: HashSet<String> = accept_ch_val
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !hints.is_empty() {
                    self.accept_ch_cache
                        .write()
                        .await
                        .entry(origin_key)
                        .or_insert_with(HashSet::new)
                        .extend(hints);
                }
            }

            if status.is_redirection() {
                if let Some(location) = resp.headers().get("location") {
                    let location_str = location.to_str().map_err(|_| {
                        ObscuraNetError::Network("Invalid redirect Location".into())
                    })?;
                    let next_url = current_url.join(location_str).map_err(|e| {
                        ObscuraNetError::Network(format!("Invalid redirect URL: {}", e))
                    })?;
                    redirects.push(current_url.clone());
                    current_url = next_url;
                    continue;
                }
            }

            let body = resp
                .bytes()
                .await
                .map_err(|e| ObscuraNetError::Network(format!("Failed to read body: {}", e)))?
                .to_vec();

            return Ok(Response {
                url: current_url,
                status: status.as_u16(),
                headers: response_headers,
                body,
                redirected_from: redirects,
            });
        }

        Err(ObscuraNetError::TooManyRedirects(url.to_string()))
    }

    pub async fn set_extra_headers(&self, headers: HashMap<String, String>) {
        *self.extra_headers.write().await = headers;
    }

    pub fn active_requests(&self) -> u32 {
        self.in_flight.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn is_network_idle(&self) -> bool {
        self.active_requests() == 0
    }
}
