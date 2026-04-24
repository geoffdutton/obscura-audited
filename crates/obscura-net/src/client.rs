use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use reqwest::redirect::Policy;
use reqwest::{Client, Method};
use tokio::sync::RwLock;
use url::Url;

use crate::cookies::CookieJar;
use crate::interceptor::{InterceptAction, RequestInterceptor};

#[derive(Debug, Clone)]
pub struct Response {
    pub url: Url,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub redirected_from: Vec<Url>,
}

impl Response {
    pub fn text(&self) -> Result<String, std::string::FromUtf8Error> {
        String::from_utf8(self.body.clone())
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    pub fn is_html(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("text/html"))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub url: Url,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub resource_type: ResourceType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceType {
    Document,
    Script,
    Stylesheet,
    Image,
    Font,
    Xhr,
    Fetch,
    Other,
}

pub type RequestCallback = Arc<dyn Fn(&RequestInfo) + Send + Sync>;
pub type ResponseCallback = Arc<dyn Fn(&RequestInfo, &Response) + Send + Sync>;

/// Address-space classification for Private Network Access (PNA) checks.
///
/// Mirrors Chromium's three-tier model: `Public` (internet), `Private`
/// (RFC1918, link-local, ULA IPv6), `Local` (loopback, `localhost`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSpace {
    Public,
    Private,
    Local,
}

impl AddressSpace {
    /// Lower rank = more private. A request is blocked when the target rank
    /// is strictly less than the initiator rank.
    fn privacy_rank(self) -> u8 {
        match self {
            AddressSpace::Local => 0,
            AddressSpace::Private => 1,
            AddressSpace::Public => 2,
        }
    }
}

fn ipv6_is_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.octets()[0] & 0xfe) == 0xfc
}

/// Classify a URL's host into one of Chromium's PNA address spaces. URLs with
/// no host (e.g. `data:`, `about:blank`) are classified as `Public` so that
/// requests originating from them are treated conservatively.
pub fn classify_address_space(url: &Url) -> AddressSpace {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => {
            if ip.is_loopback() {
                AddressSpace::Local
            } else if ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
            {
                AddressSpace::Private
            } else {
                AddressSpace::Public
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if ip.is_loopback() {
                AddressSpace::Local
            } else if ip.is_unicast_link_local() || ipv6_is_unique_local(&ip) {
                AddressSpace::Private
            } else {
                AddressSpace::Public
            }
        }
        Some(url::Host::Domain(domain)) => {
            let lower = domain.to_lowercase();
            if lower == "localhost" || lower.ends_with(".localhost") {
                AddressSpace::Local
            } else {
                AddressSpace::Public
            }
        }
        None => AddressSpace::Public,
    }
}

/// Context in which an outbound request is being made.
///
/// `TopLevel` is a user-initiated navigation (CLI `obscura fetch`, the initial
/// page load). Chromium does not apply PNA to top-level navigations, and
/// neither do we — scheme restrictions still apply.
///
/// `Page(&Url)` is a page-initiated subresource request (`fetch()`, `import`,
/// `<script src>`, `<link rel=stylesheet>`). The initiator URL's address space
/// gates access to more-private targets.
pub enum RequestInitiator<'a> {
    TopLevel,
    Page(&'a Url),
}

/// Enforce PNA: block page-initiated requests that step toward a more-private
/// address space than the initiator. Top-level navigations are subject only
/// to scheme restrictions.
pub fn validate_pna(target: &Url, initiator: RequestInitiator<'_>) -> Result<(), String> {
    let scheme = target.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "Forbidden URL scheme '{}' - only http and https are allowed",
            scheme
        ));
    }

    let initiator_url = match initiator {
        RequestInitiator::TopLevel => return Ok(()),
        RequestInitiator::Page(url) => url,
    };

    let initiator_space = classify_address_space(initiator_url);
    let target_space = classify_address_space(target);

    if target_space.privacy_rank() < initiator_space.privacy_rank() {
        return Err(format!(
            "Private Network Access: page at {} ({:?}) may not request {} ({:?})",
            initiator_url, initiator_space, target, target_space,
        ));
    }

    Ok(())
}

fn validate_url(url: &Url, initiator: RequestInitiator<'_>) -> Result<(), ObscuraNetError> {
    validate_pna(url, initiator).map_err(ObscuraNetError::Network)
}

pub struct ObscuraHttpClient {
    client: tokio::sync::OnceCell<Client>,
    proxy_url: Option<String>,
    pub cookie_jar: Arc<CookieJar>,
    pub user_agent: RwLock<String>,
    pub extra_headers: RwLock<HashMap<String, String>>,
    pub interceptor: RwLock<Option<Box<dyn RequestInterceptor + Send + Sync>>>,
    pub on_request: RwLock<Vec<RequestCallback>>,
    pub on_response: RwLock<Vec<ResponseCallback>>,
    pub timeout: Duration,
    pub in_flight: Arc<std::sync::atomic::AtomicU32>,
    pub block_trackers: bool,
}

impl ObscuraHttpClient {
    pub fn new() -> Self {
        Self::with_cookie_jar(Arc::new(CookieJar::new()))
    }

    pub fn with_cookie_jar(cookie_jar: Arc<CookieJar>) -> Self {
        Self::with_options(cookie_jar, None)
    }

    pub fn with_options(cookie_jar: Arc<CookieJar>, proxy_url: Option<&str>) -> Self {
        ObscuraHttpClient {
            client: tokio::sync::OnceCell::new(),
            proxy_url: proxy_url.map(|s| s.to_string()),
            cookie_jar,
            user_agent: RwLock::new(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36".to_string(),
            ),
            extra_headers: RwLock::new(HashMap::new()),
            interceptor: RwLock::new(None),
            on_request: RwLock::new(Vec::new()),
            on_response: RwLock::new(Vec::new()),
            in_flight: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            timeout: Duration::from_secs(30),
            block_trackers: false,
        }
    }

    async fn get_client(&self) -> &Client {
        self.client
            .get_or_init(|| async {
                let mut builder = Client::builder()
                    .redirect(Policy::none())
                    .timeout(Duration::from_secs(30))
                    .danger_accept_invalid_certs(false);

                if let Some(ref proxy) = self.proxy_url {
                    if let Ok(p) = reqwest::Proxy::all(proxy.as_str()) {
                        builder = builder.proxy(p);
                    }
                }

                builder.build().expect("failed to build HTTP client")
            })
            .await
    }

    pub async fn fetch(&self, url: &Url) -> Result<Response, ObscuraNetError> {
        self.fetch_with_method(Method::GET, url, None, RequestInitiator::TopLevel)
            .await
    }

    pub async fn fetch_subresource(
        &self,
        url: &Url,
        initiator: &Url,
    ) -> Result<Response, ObscuraNetError> {
        self.fetch_with_method(Method::GET, url, None, RequestInitiator::Page(initiator))
            .await
    }

    pub async fn post_form(&self, url: &Url, body: &str) -> Result<Response, ObscuraNetError> {
        self.fetch_with_method(
            Method::POST,
            url,
            Some(body.as_bytes().to_vec()),
            RequestInitiator::TopLevel,
        )
        .await
    }

    pub async fn fetch_with_method(
        &self,
        initial_method: Method,
        url: &Url,
        initial_body: Option<Vec<u8>>,
        initiator: RequestInitiator<'_>,
    ) -> Result<Response, ObscuraNetError> {
        validate_url(
            url,
            match initiator {
                RequestInitiator::TopLevel => RequestInitiator::TopLevel,
                RequestInitiator::Page(u) => RequestInitiator::Page(u),
            },
        )?;
        let redirect_initiator = match initiator {
            RequestInitiator::TopLevel => None,
            RequestInitiator::Page(u) => Some(u.clone()),
        };

        let mut method = initial_method;
        let mut body = initial_body;
        if self.block_trackers {
            if let Some(host) = url.host_str() {
                if crate::blocklist::is_blocked(host) {
                    tracing::debug!("Blocked tracker: {}", url);
                    return Ok(Response {
                        status: 0,
                        url: url.clone(),
                        headers: HashMap::new(),
                        body: Vec::new(),
                        redirected_from: Vec::new(),
                    });
                }
            }
        }

        let mut current_url = url.clone();
        let mut redirects = Vec::new();
        let max_redirects = 20;

        for _redirect_count in 0..max_redirects {
            let request_info = RequestInfo {
                url: current_url.clone(),
                method: method.to_string(),
                headers: self.extra_headers.read().await.clone(),
                resource_type: ResourceType::Document,
            };

            if let Some(interceptor) = self.interceptor.read().await.as_ref() {
                match interceptor.intercept(&request_info).await {
                    InterceptAction::Continue => {}
                    InterceptAction::Block => {
                        return Err(ObscuraNetError::Blocked(current_url.to_string()));
                    }
                    InterceptAction::Fulfill(response) => {
                        return Ok(response);
                    }
                    InterceptAction::ModifyHeaders(headers) => {
                        let mut extra = self.extra_headers.write().await;
                        extra.extend(headers);
                    }
                }
            }

            for cb in self.on_request.read().await.iter() {
                cb(&request_info);
            }

            let ua = self.user_agent.read().await.clone();
            let mut headers = HeaderMap::new();
            headers.insert(USER_AGENT, HeaderValue::from_str(&ua).unwrap_or_else(|_| {
                HeaderValue::from_static("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36")
            }));
            headers.insert(
                reqwest::header::ACCEPT,
                HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"),
            );
            headers.insert(
                reqwest::header::ACCEPT_LANGUAGE,
                HeaderValue::from_static("en-US,en;q=0.9"),
            );
            headers.insert(
                HeaderName::from_static("sec-ch-ua"),
                HeaderValue::from_static(
                    "\"Chromium\";v=\"145\", \"Not;A=Brand\";v=\"24\", \"Google Chrome\";v=\"145\"",
                ),
            );
            headers.insert(
                HeaderName::from_static("sec-ch-ua-mobile"),
                HeaderValue::from_static("?0"),
            );
            headers.insert(
                HeaderName::from_static("sec-ch-ua-platform"),
                HeaderValue::from_static("\"Linux\""),
            );
            headers.insert(
                HeaderName::from_static("sec-fetch-dest"),
                HeaderValue::from_static("document"),
            );
            headers.insert(
                HeaderName::from_static("sec-fetch-mode"),
                HeaderValue::from_static("navigate"),
            );
            headers.insert(
                HeaderName::from_static("sec-fetch-site"),
                HeaderValue::from_static("none"),
            );
            headers.insert(
                HeaderName::from_static("sec-fetch-user"),
                HeaderValue::from_static("?1"),
            );
            headers.insert(
                HeaderName::from_static("upgrade-insecure-requests"),
                HeaderValue::from_static("1"),
            );

            let cookie_header = self.cookie_jar.get_cookie_header(&current_url);
            if !cookie_header.is_empty() {
                if let Ok(val) = HeaderValue::from_str(&cookie_header) {
                    headers.insert(reqwest::header::COOKIE, val);
                }
            }

            for (k, v) in self.extra_headers.read().await.iter() {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    headers.insert(name, val);
                }
            }

            let mut req_builder = self
                .get_client()
                .await
                .request(method.clone(), current_url.as_str())
                .headers(headers);

            if let Some(ref b) = body {
                if method == Method::POST {
                    req_builder = req_builder.header(
                        reqwest::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    );
                }
                req_builder = req_builder.body(b.clone());
            }

            self.in_flight
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let resp = req_builder.send().await.map_err(|e| {
                self.in_flight
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                ObscuraNetError::Network(format!("{}: {}", current_url, e))
            })?;
            self.in_flight
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

            let status = resp.status();

            for val in resp.headers().get_all(reqwest::header::SET_COOKIE) {
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

            if status.is_redirection() {
                if let Some(location) = resp.headers().get(reqwest::header::LOCATION) {
                    let location_str = location.to_str().map_err(|_| {
                        ObscuraNetError::Network("Invalid redirect Location header".into())
                    })?;
                    let next_url = current_url.join(location_str).map_err(|e| {
                        ObscuraNetError::Network(format!("Invalid redirect URL: {}", e))
                    })?;
                    let redirect_ctx = match redirect_initiator.as_ref() {
                        Some(u) => RequestInitiator::Page(u),
                        None => RequestInitiator::TopLevel,
                    };
                    validate_url(&next_url, redirect_ctx)?;
                    redirects.push(current_url.clone());
                    current_url = next_url;
                    if status == reqwest::StatusCode::MOVED_PERMANENTLY
                        || status == reqwest::StatusCode::FOUND
                        || status == reqwest::StatusCode::SEE_OTHER
                    {
                        method = Method::GET;
                        body = None;
                    }
                    continue;
                }
            }

            let body_bytes = resp
                .bytes()
                .await
                .map_err(|e| ObscuraNetError::Network(format!("Failed to read body: {}", e)))?
                .to_vec();

            let response = Response {
                url: current_url,
                status: status.as_u16(),
                headers: response_headers,
                body: body_bytes,
                redirected_from: redirects,
            };

            for cb in self.on_response.read().await.iter() {
                cb(&request_info, &response);
            }

            return Ok(response);
        }

        Err(ObscuraNetError::TooManyRedirects(current_url.to_string()))
    }

    pub async fn set_user_agent(&self, ua: &str) {
        *self.user_agent.write().await = ua.to_string();
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

impl Default for ObscuraHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ObscuraNetError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Too many redirects: {0}")]
    TooManyRedirects(String),

    #[error("Request blocked: {0}")]
    Blocked(String),
}

#[cfg(test)]
mod pna_tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).expect("valid URL")
    }

    #[test]
    fn classifies_ipv4_loopback_as_local() {
        assert_eq!(
            classify_address_space(&u("http://127.0.0.1/")),
            AddressSpace::Local
        );
        assert_eq!(
            classify_address_space(&u("http://127.0.0.5/")),
            AddressSpace::Local
        );
    }

    #[test]
    fn classifies_ipv6_loopback_as_local() {
        assert_eq!(
            classify_address_space(&u("http://[::1]/")),
            AddressSpace::Local
        );
    }

    #[test]
    fn classifies_localhost_hostname_as_local() {
        assert_eq!(
            classify_address_space(&u("http://localhost/")),
            AddressSpace::Local
        );
        assert_eq!(
            classify_address_space(&u("http://LOCALHOST/")),
            AddressSpace::Local
        );
        assert_eq!(
            classify_address_space(&u("http://foo.localhost/")),
            AddressSpace::Local
        );
    }

    #[test]
    fn classifies_rfc1918_as_private() {
        assert_eq!(
            classify_address_space(&u("http://10.0.0.1/")),
            AddressSpace::Private
        );
        assert_eq!(
            classify_address_space(&u("http://192.168.1.1/")),
            AddressSpace::Private
        );
        assert_eq!(
            classify_address_space(&u("http://172.16.0.1/")),
            AddressSpace::Private
        );
        assert_eq!(
            classify_address_space(&u("http://172.31.255.255/")),
            AddressSpace::Private
        );
    }

    #[test]
    fn classifies_edge_of_rfc1918_correctly() {
        assert_eq!(
            classify_address_space(&u("http://172.15.0.1/")),
            AddressSpace::Public
        );
        assert_eq!(
            classify_address_space(&u("http://172.32.0.1/")),
            AddressSpace::Public
        );
    }

    #[test]
    fn classifies_ipv4_link_local_as_private() {
        assert_eq!(
            classify_address_space(&u("http://169.254.1.1/")),
            AddressSpace::Private
        );
        assert_eq!(
            classify_address_space(&u("http://169.254.169.254/")),
            AddressSpace::Private
        );
    }

    #[test]
    fn classifies_ipv6_ula_as_private() {
        assert_eq!(
            classify_address_space(&u("http://[fc00::1]/")),
            AddressSpace::Private
        );
        assert_eq!(
            classify_address_space(&u("http://[fd12:3456::1]/")),
            AddressSpace::Private
        );
    }

    #[test]
    fn classifies_ipv6_link_local_as_private() {
        assert_eq!(
            classify_address_space(&u("http://[fe80::1]/")),
            AddressSpace::Private
        );
    }

    #[test]
    fn classifies_public_addresses_as_public() {
        assert_eq!(
            classify_address_space(&u("http://8.8.8.8/")),
            AddressSpace::Public
        );
        assert_eq!(
            classify_address_space(&u("http://example.com/")),
            AddressSpace::Public
        );
        assert_eq!(
            classify_address_space(&u("http://[2001:db8::1]/")),
            AddressSpace::Public
        );
    }

    #[test]
    fn rejects_non_http_scheme_regardless_of_initiator() {
        assert!(validate_pna(&u("file:///etc/passwd"), RequestInitiator::TopLevel).is_err());
        assert!(validate_pna(&u("ftp://example.com/"), RequestInitiator::TopLevel).is_err());
        let page = u("https://example.com/");
        assert!(validate_pna(&u("file:///etc/passwd"), RequestInitiator::Page(&page)).is_err());
    }

    #[test]
    fn top_level_navigation_allowed_to_any_space() {
        assert!(validate_pna(&u("http://localhost:3000/"), RequestInitiator::TopLevel).is_ok());
        assert!(validate_pna(&u("http://127.0.0.1/"), RequestInitiator::TopLevel).is_ok());
        assert!(validate_pna(&u("http://192.168.1.1/"), RequestInitiator::TopLevel).is_ok());
        assert!(validate_pna(&u("http://169.254.169.254/"), RequestInitiator::TopLevel).is_ok());
        assert!(validate_pna(&u("https://example.com/"), RequestInitiator::TopLevel).is_ok());
    }

    #[test]
    fn page_public_to_local_is_blocked() {
        let page = u("https://example.com/");
        let err = validate_pna(&u("http://localhost:3000/"), RequestInitiator::Page(&page))
            .expect_err("public page must not reach localhost");
        assert!(err.contains("Private Network Access"), "got: {}", err);

        assert!(validate_pna(&u("http://127.0.0.1/"), RequestInitiator::Page(&page)).is_err());
        assert!(validate_pna(&u("http://[::1]/"), RequestInitiator::Page(&page)).is_err());
    }

    #[test]
    fn page_public_to_private_is_blocked() {
        let page = u("https://example.com/");
        assert!(validate_pna(&u("http://10.0.0.1/"), RequestInitiator::Page(&page)).is_err());
        assert!(
            validate_pna(&u("http://169.254.169.254/"), RequestInitiator::Page(&page)).is_err()
        );
        assert!(validate_pna(&u("http://192.168.1.1/"), RequestInitiator::Page(&page)).is_err());
    }

    #[test]
    fn page_public_to_public_is_allowed() {
        let page = u("https://example.com/");
        assert!(validate_pna(
            &u("https://other.example.org/"),
            RequestInitiator::Page(&page)
        )
        .is_ok());
        assert!(validate_pna(&u("http://8.8.8.8/"), RequestInitiator::Page(&page)).is_ok());
    }

    #[test]
    fn page_private_to_local_is_blocked() {
        let page = u("http://10.0.0.5/");
        assert!(validate_pna(&u("http://localhost/"), RequestInitiator::Page(&page)).is_err());
        assert!(validate_pna(&u("http://127.0.0.1/"), RequestInitiator::Page(&page)).is_err());
    }

    #[test]
    fn page_private_to_private_is_allowed() {
        let page = u("http://10.0.0.5/");
        assert!(validate_pna(&u("http://192.168.1.1/"), RequestInitiator::Page(&page)).is_ok());
        assert!(validate_pna(&u("http://10.0.0.6/"), RequestInitiator::Page(&page)).is_ok());
    }

    #[test]
    fn page_private_to_public_is_allowed() {
        let page = u("http://10.0.0.5/");
        assert!(validate_pna(&u("https://example.com/"), RequestInitiator::Page(&page)).is_ok());
    }

    #[test]
    fn page_local_to_anything_is_allowed() {
        let page = u("http://localhost:3000/");
        assert!(validate_pna(&u("http://127.0.0.1/"), RequestInitiator::Page(&page)).is_ok());
        assert!(validate_pna(&u("http://10.0.0.1/"), RequestInitiator::Page(&page)).is_ok());
        assert!(validate_pna(&u("https://example.com/"), RequestInitiator::Page(&page)).is_ok());
    }

    #[test]
    fn unparseable_origin_treated_as_public_initiator() {
        // A page with no host (e.g. data: or about:blank) should default to the
        // most restrictive initiator so it cannot reach private networks.
        let no_host = u("data:text/html,hello");
        assert!(validate_pna(&u("http://localhost/"), RequestInitiator::Page(&no_host)).is_err());
        assert!(validate_pna(&u("https://example.com/"), RequestInitiator::Page(&no_host)).is_ok());
    }
}
