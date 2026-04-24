use serde_json::{json, Value};

pub async fn handle(method: &str, _params: &Value) -> Result<Value, String> {
    match method {
        "getVersion" => Ok(json!({
            "protocolVersion": "1.3",
            "product": "Obscura/0.1.0",
            "revision": "0",
            "userAgent": "Obscura/0.1.0 (Headless Browser)",
            "jsVersion": "N/A",
        })),
        "close" => Ok(json!({})),
        "getWindowForTarget" => Ok(json!({
            "windowId": 1,
            "bounds": {
                "left": 0,
                "top": 0,
                "width": 1280,
                "height": 720,
                "windowState": "normal",
            }
        })),
        "setDownloadBehavior" => Ok(json!({})),
        "getWindowBounds" => Ok(json!({
            "bounds": { "left": 0, "top": 0, "width": 1280, "height": 720, "windowState": "normal" }
        })),
        _ => Err(format!("Unknown Browser method: {}", method)),
    }
}
