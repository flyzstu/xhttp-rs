//! Clash API server: exposes the outbound groups (selector/urltest) and the
//! current mode over an HTTP API compatible with Clash dashboards such as
//! Yacd-meta. It is a read/switch surface on top of `ProxyRuntime`; the data
//! plane is untouched.

use crate::proxy::{GroupKind, ProxyRuntime};
use crate::singbox::ClashApiConfig;
use anyhow::{Context, Result};
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};
use std::net::SocketAddr;

#[derive(Clone)]
struct ApiState {
    runtime: ProxyRuntime,
    secret: Option<String>,
}

pub async fn run(config: ClashApiConfig, runtime: ProxyRuntime) -> Result<()> {
    let address: SocketAddr = config
        .external_controller
        .as_deref()
        .context("clash_api external_controller required")?
        .parse()
        .context("invalid external_controller address")?;
    let state = ApiState {
        runtime,
        secret: config.secret.filter(|value| !value.is_empty()),
    };
    let mut app = Router::new()
        .route("/version", get(version))
        .route("/configs", get(get_configs).patch(patch_configs))
        .route("/proxies", get(get_proxies))
        .route("/proxies/{name}", get(get_proxy).put(update_proxy))
        .route("/proxies/{name}/delay", get(proxy_delay))
        .with_state(state);
    if let Some(ui_dir) = config.external_ui.filter(|value| !value.is_empty()) {
        ensure_ui(&ui_dir, config.external_ui_download_url.as_deref()).await?;
        app = app.nest_service(
            "/ui",
            tower_http::services::ServeDir::new(&ui_dir).append_index_html_on_directories(true),
        );
    }
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .with_context(|| format!("bind clash API on {address}"))?;
    axum::serve(listener, app).await.context("clash API server failed")
}

/// Download and extract the Yacd-meta dashboard into `ui_dir` if it is empty.
async fn ensure_ui(ui_dir: &str, download_url: Option<&str>) -> Result<()> {
    if std::fs::read_dir(ui_dir).is_ok_and(|mut entries| entries.next().is_some()) {
        return Ok(());
    }
    std::fs::create_dir_all(ui_dir).ok();
    let url = download_url
        .unwrap_or("https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip")
        .to_owned();
    tracing::info!("downloading Yacd-meta dashboard from {url}");
    let bytes = tokio::task::spawn_blocking(move || {
        let response = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .context("build UI download client")?
            .get(&url)
            .send()
            .context("download external UI")?
            .error_for_status()
            .context("external UI download failed")?
            .bytes()
            .context("read external UI archive")?;
        Ok::<Vec<u8>, anyhow::Error>(response.to_vec())
    })
    .await
    .context("external UI download task failed")??;
    tracing::info!("downloaded {} bytes of Yacd-meta dashboard", bytes.len());
    let cursor = std::io::Cursor::new(bytes);
    let mut archive =
        zip::ZipArchive::new(cursor).context("open external UI archive")?;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .context("read external UI archive entry")?;
        // Yacd-meta's gh-pages zip nests everything under a single directory.
        let relative = file.name().split('/').skip(1).collect::<Vec<_>>().join("/");
        if relative.is_empty() {
            continue;
        }
        let path = std::path::Path::new(ui_dir).join(&relative);
        if file.is_dir() {
            std::fs::create_dir_all(&path).ok();
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let mut output = std::fs::File::create(&path)
            .with_context(|| format!("create UI file {}", path.display()))?;
        std::io::copy(&mut file, &mut output).context("extract UI archive entry")?;
    }
    Ok(())
}

fn authenticated(headers: &HeaderMap, secret: Option<&str>) -> bool {
    let Some(secret) = secret else {
        return true;
    };
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {secret}"))
}

async fn version(State(state): State<ApiState>) -> Response {
    if !authenticated(&HeaderMap::new(), state.secret.as_deref()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    json_response(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "premium": false,
        "meta": true,
    }))
}

async fn get_configs(State(state): State<ApiState>) -> Response {
    if !authenticated(&HeaderMap::new(), state.secret.as_deref()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    json_response(json!({
        "mode": state.runtime.clash_mode().unwrap_or_else(|| "rule".into()),
        "mode-list": ["rule", "global", "direct"],
        "port": 0,
        "socks-port": 0,
        "mixed-port": 0,
        "allow-lan": false,
        "bind-address": "*",
        "log-level": "info",
        "ipv6": false,
    }))
}

async fn patch_configs(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !authenticated(&headers, state.secret.as_deref()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let bytes = match axum::body::to_bytes(body, 1024 * 64).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Ok(patch) = serde_json::from_slice::<Value>(&bytes) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if let Some(mode) = patch
        .get("mode")
        .and_then(Value::as_str)
        .filter(|mode| matches!(*mode, "rule" | "global" | "direct"))
    {
        state.runtime.set_clash_mode(Some(mode.to_owned()));
    }
    StatusCode::NO_CONTENT.into_response()
}

/// One proxy entry: a selector/urltest group or a leaf outbound.
fn proxy_entry(runtime: &ProxyRuntime, tag: &str) -> Value {
    if let Some(group) = runtime.group(tag) {
        let kind = match group.kind() {
            GroupKind::Selector => "Selector",
            GroupKind::UrlTest => "URLTest",
        };
        return json!({
            "type": kind,
            "name": tag,
            "udp": true,
            "now": group.now(),
            "all": group.all(),
        });
    }
    let Some(dialer) = runtime.dialer_for(tag) else {
        return json!({ "type": "Direct", "name": tag, "udp": true, "history": [] });
    };
    json!({
        "type": dialer.clash_type(),
        "name": tag,
        "udp": true,
        "history": [],
    })
}

async fn get_proxies(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    if !authenticated(&headers, state.secret.as_deref()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let tags = state.runtime.outbound_tags();
    let mut proxies = serde_json::Map::new();
    // A GLOBAL selector lets dashboards switch the default outbound.
    proxies.insert(
        "GLOBAL".into(),
        json!({
            "type": "Selector",
            "name": "GLOBAL",
            "udp": true,
            "now": tags.first().cloned().unwrap_or_else(|| "direct".into()),
            "all": tags,
        }),
    );
    for tag in state.runtime.outbound_tags() {
        let entry = proxy_entry(&state.runtime, &tag);
        if let Some(name) = entry.get("name").and_then(Value::as_str) {
            proxies.insert(name.to_owned(), entry);
        }
    }
    json_response(json!({ "proxies": proxies }))
}

async fn get_proxy(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !authenticated(&headers, state.secret.as_deref()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !state.runtime.is_group(&name) && state.runtime.dialer_for(&name).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    json_response(proxy_entry(&state.runtime, &name))
}

async fn update_proxy(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !authenticated(&headers, state.secret.as_deref()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let bytes = match axum::body::to_bytes(body, 1024 * 64).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let Ok(update) = serde_json::from_slice::<Value>(&bytes) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(member) = update.get("name").and_then(Value::as_str) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if name == "GLOBAL" {
        // GLOBAL is the default outbound: switching it changes the route fallback.
        if state.runtime.dialer_for(member).is_none() && !state.runtime.is_group(member) {
            return StatusCode::BAD_REQUEST.into_response();
        }
        state.runtime.set_final_outbound(member);
        return StatusCode::NO_CONTENT.into_response();
    }
    let Some(group) = state.runtime.group(&name) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !group.select(member) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn proxy_delay(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !authenticated(&headers, state.secret.as_deref()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Some(dialer) = state.runtime.dialer_for(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = "http://www.gstatic.com/generate_204";
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        dialer.probe_delay(url),
    )
    .await
    {
        Ok(Some(delay)) => json_response(json!({ "delay": delay })),
        _ => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn json_response(value: Value) -> Response {
    (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "application/json")], value.to_string())
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::build_runtime;
    use crate::singbox::{Outbound, RouteConfig};

    async fn selector_runtime() -> ProxyRuntime {
        let outbounds = vec![
            Outbound {
                r#type: "direct".into(),
                tag: Some("direct".into()),
                ..Default::default()
            },
            Outbound {
                r#type: "selector".into(),
                tag: Some("proxy".into()),
                outbounds: vec!["direct".into()],
                default: Some("direct".into()),
                ..Default::default()
            },
        ];
        build_runtime(outbounds, Some(RouteConfig::default()), None)
            .await
            .unwrap()
    }

    async fn free_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn clash_api_exposes_groups_and_switches_nodes() {
        let runtime = selector_runtime().await;
        let port = free_port().await;
        let config = ClashApiConfig {
            external_controller: Some(format!("127.0.0.1:{port}")),
            secret: None,
            external_ui: None,
            external_ui_download_url: None,
        };
        let server = tokio::spawn(run(config, runtime));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{port}");

        // /proxies lists GLOBAL selector plus the group and leaf.
        let proxies: Value = client
            .get(format!("{base}/proxies"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let proxies_map = proxies["proxies"].as_object().unwrap();
        assert!(proxies_map.contains_key("GLOBAL"));
        let global = &proxies_map["GLOBAL"];
        assert_eq!(global["type"], "Selector");
        assert_eq!(global["now"], "proxy");
        assert!(global["all"].as_array().unwrap().iter().any(|t| t == "proxy"));

        // The selector group itself appears as a proxy entry.
        let proxy_group = &proxies_map["proxy"];
        assert_eq!(proxy_group["type"], "Selector");
        assert_eq!(proxy_group["now"], "direct");
        assert!(proxy_group["all"].as_array().unwrap().contains(&Value::String("direct".into())));

        // Switching the GLOBAL selection to the proxy group works.
        let status = client
            .put(format!("{base}/proxies/GLOBAL"))
            .json(&json!({ "name": "proxy" }))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 204);

        // Switching the selector group's member works.
        let status = client
            .put(format!("{base}/proxies/proxy"))
            .json(&json!({ "name": "direct" }))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 204);

        server.abort();
    }

    #[tokio::test]
    async fn clash_api_configs_read_and_write_mode() {
        let runtime = selector_runtime().await;
        let port = free_port().await;
        let config = ClashApiConfig {
            external_controller: Some(format!("127.0.0.1:{port}")),
            secret: None,
            external_ui: None,
            external_ui_download_url: None,
        };
        let server = tokio::spawn(run(config, runtime));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = reqwest::Client::new();
        let base = format!("http://127.0.0.1:{port}");

        let configs: Value = client.get(format!("{base}/configs")).send().await.unwrap().json().await.unwrap();
        assert_eq!(configs["mode"], "rule");

        let status = client
            .patch(format!("{base}/configs"))
            .json(&json!({ "mode": "global" }))
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, 204);

        let configs: Value = client.get(format!("{base}/configs")).send().await.unwrap().json().await.unwrap();
        assert_eq!(configs["mode"], "global");

        server.abort();
    }
}
