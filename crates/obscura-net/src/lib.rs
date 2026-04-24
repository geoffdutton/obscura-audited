pub mod client;
pub mod cookies;
pub mod interceptor;
pub mod robots;
pub mod blocklist;
#[cfg(feature = "stealth")]
pub mod wreq_client;

pub use client::{
    classify_address_space, validate_pna, AddressSpace, ObscuraHttpClient, ObscuraNetError,
    RequestInfo, RequestInitiator, ResourceType, Response,
};
pub use cookies::{CookieInfo, CookieJar};
pub use robots::RobotsCache;
pub use blocklist::is_blocked as is_tracker_blocked;
#[cfg(feature = "stealth")]
pub use wreq_client::{StealthHttpClient, STEALTH_USER_AGENT};
