//! Protocol-codec benchmarks against the real `xhttp::protocol` API.
//! No simulated matchers: every case calls the production functions on realistic
//! session metadata, headers and payloads.

#[path = "common/mod.rs"]
mod common;

use axum::http::{HeaderMap, HeaderValue, Uri};
use common::{Config, measure_sync, print_header};
use std::hint::black_box;
use url::Url;
use xhttp::{
    config::{Mode, Placement, TransportConfig},
    protocol,
};

fn config() -> TransportConfig {
    TransportConfig {
        path: "/xhttp".into(),
        mode: Mode::StreamUp,
        session_placement: Placement::Path,
        sequence_placement: Placement::Query,
        data_placement: Placement::Body,
        token: Some("bench-token".into()),
        ..Default::default()
    }
}

fn uri() -> Uri {
    "/xhttp/session-abc123?x_seq=42&x_padding=xxxxxxxxxxxxxxxx"
        .parse()
        .unwrap()
}

fn headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "authorization",
        HeaderValue::from_static("Bearer bench-token"),
    );
    h.insert("x_client", HeaderValue::from_static("bench"));
    h.insert("x_sequence", HeaderValue::from_static("42"));
    h
}

fn main() {
    let cfg = Config::new(2_000, 20_000, 7);
    let conf = config();

    print_header("protocol codec");
    measure_sync("add_common_headers", &cfg, || {
        let mut h = HeaderMap::new();
        protocol::add_common_headers(&conf, &mut h).unwrap();
        black_box(h);
    })
    .report();
    measure_sync("apply_padding", &cfg, || {
        let mut url = Url::parse("https://example.com/xhttp").unwrap();
        let mut h = HeaderMap::new();
        protocol::apply_padding(&conf, &mut url, &mut h);
        black_box((url, h));
    })
    .report();
    let uri = uri();
    let h = headers();
    measure_sync("extract_metadata", &cfg, || {
        let meta = protocol::extract_metadata(&conf, &uri, &h);
        black_box(meta);
    })
    .report();
    measure_sync("authorized", &cfg, || {
        black_box(protocol::authorized(&conf, &h));
    })
    .report();

    let payload = vec![0x5a_u8; 4096];
    measure_sync("put_payload (body)", &cfg, || {
        let mut h = HeaderMap::new();
        black_box(protocol::put_payload(&conf, &payload, &mut h).unwrap());
    })
    .report();
    let body = vec![0x5a_u8; 4096];
    measure_sync("extract_payload (body)", &cfg, || {
        black_box(protocol::extract_payload(&conf, &h, &body).unwrap());
    })
    .report();

    let mut conf_hdr = config();
    conf_hdr.data_placement = Placement::Header;
    conf_hdr.data_key = "X-Data".into();
    measure_sync("put_payload (header,4k)", &cfg, || {
        let mut h = HeaderMap::new();
        black_box(protocol::put_payload(&conf_hdr, &payload, &mut h).unwrap());
    })
    .report();
    let mut hh = HeaderMap::new();
    protocol::put_payload(&conf_hdr, &payload, &mut hh).unwrap();
    measure_sync("extract_payload (header,4k)", &cfg, || {
        black_box(protocol::extract_payload(&conf_hdr, &hh, &[]).unwrap());
    })
    .report();

    measure_sync("apply_response_padding", &cfg, || {
        let mut h = HeaderMap::new();
        protocol::apply_response_padding(&conf, &mut h);
        black_box(h);
    })
    .report();
}
