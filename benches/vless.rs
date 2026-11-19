//! VLESS protocol codec benchmarks against the real `xhttp::vless` API.
//! `write_request`/`read_response` run against in-memory Tokio streams so the
//! measured work is serialization, not network I/O.

#[path = "common/mod.rs"]
mod common;

use common::{Config, measure_async, measure_sync, print_header};
use std::hint::black_box;
use xhttp::vless;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn main() {
    let cfg = Config::new(2_000, 20_000, 7);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build benchmark runtime");

    let domain = vless::parse_destination("example.com", 443);
    let ip4 = vless::parse_destination("1.2.3.4", 80);
    let ip6 = vless::parse_destination("2001:db8::1", 443);

    print_header("vless codec");
    measure_sync("parse_destination (domain)", &cfg, || {
        black_box(vless::parse_destination("example.com", 443));
    })
    .report();
    measure_sync("parse_destination (ipv4)", &cfg, || {
        black_box(vless::parse_destination("1.2.3.4", 80));
    })
    .report();

    runtime.block_on(async {
        measure_async("write_request (domain,TCP)", &cfg, || async {
            let mut sink = tokio::io::sink();
            vless::write_request(&mut sink, UUID, &domain)
                .await
                .unwrap();
        })
        .await
        .report();
        measure_async("write_request (ipv4,TCP)", &cfg, || async {
            let mut sink = tokio::io::sink();
            vless::write_request(&mut sink, UUID, &ip4).await.unwrap();
        })
        .await
        .report();
        measure_async("write_request (ipv6,TCP)", &cfg, || async {
            let mut sink = tokio::io::sink();
            vless::write_request(&mut sink, UUID, &ip6).await.unwrap();
        })
        .await
        .report();
        measure_async("write_request (XUDP command)", &cfg, || async {
            let mut sink = tokio::io::sink();
            vless::write_request_with_command(&mut sink, UUID, vless::Command::Xudp, &domain)
                .await
                .unwrap();
        })
        .await
        .report();
        measure_async("read_response", &cfg, || async {
            let mut data: &[u8] = &[0, 0];
            vless::read_response(&mut data).await.unwrap();
        })
        .await
        .report();
    });
}
