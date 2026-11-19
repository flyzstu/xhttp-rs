//! Routing benchmarks against the REAL `xhttp::routing::Router` engine.
//! The previous version used simulated matchers; this one compiles and queries
//! production `RouteConfig`/`RouteRule`/`Router` so regressions in rule
//! compilation or matching are actually caught.

#[path = "common/mod.rs"]
mod common;

use common::{Config, measure_sync, print_header};
use std::hint::black_box;
use xhttp::{
    routing::{RouteContext, Router},
    singbox::{RouteConfig, RouteRule},
};

fn config() -> RouteConfig {
    RouteConfig {
        rules: vec![
            RouteRule {
                domain_suffix: vec![".example.com".into(), ".example.net".into()],
                outbound: Some("proxy".into()),
                ..Default::default()
            },
            RouteRule {
                domain_keyword: vec!["ads".into(), "tracker".into(), "analytics".into()],
                action: Some("reject".into()),
                ..Default::default()
            },
            RouteRule {
                ip_cidr: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
                outbound: Some("direct".into()),
                ..Default::default()
            },
            RouteRule {
                port: vec![80, 443, 8080],
                network: vec!["tcp".into()],
                outbound: Some("proxy".into()),
                ..Default::default()
            },
            RouteRule {
                domain_regex: vec![r"^api[0-9]+\.example\.com$".into()],
                outbound: Some("api".into()),
                ..Default::default()
            },
        ],
        final_outbound: Some("direct".into()),
        ..Default::default()
    }
}

fn main() {
    let cfg = Config::new(2_000, 50_000, 7);
    let router = Router::compile(&config(), "direct").expect("compile benchmark router");

    let domains: Vec<String> = (0..1_000).map(|i| format!("www{i}.example.com")).collect();
    let matching_domains: Vec<String> = (0..1_000).map(|i| format!("ads{i}.com")).collect();
    let ips: Vec<std::net::IpAddr> = (0..1_000)
        .map(|i| {
            format!("10.0.{}.{}", (i / 256) % 256, i % 256)
                .parse()
                .unwrap()
        })
        .collect();

    print_header("routing (real Router)");

    measure_sync("compile Router (50 rules)", &Config::new(0, 50, 7), || {
        let big = RouteConfig {
            rules: (0..50)
                .map(|i| RouteRule {
                    domain_suffix: vec![format!(".suffix{i}.example")],
                    outbound: Some(format!("out{i}")),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        };
        black_box(Router::compile(&big, "direct").unwrap());
    })
    .report();

    measure_sync("route domain suffix hit", &cfg, || {
        let ctx = RouteContext {
            domain: Some(black_box(&domains[1])),
            network: Some("tcp"),
            destination_port: Some(443),
            ..Default::default()
        };
        black_box(router.route(&ctx));
    })
    .report();

    measure_sync("route domain keyword hit", &cfg, || {
        let ctx = RouteContext {
            domain: Some(black_box(&matching_domains[1])),
            network: Some("tcp"),
            ..Default::default()
        };
        black_box(router.route(&ctx));
    })
    .report();

    measure_sync("route ip cidr hit", &cfg, || {
        let ctx = RouteContext {
            destination_ip: Some(black_box(ips[1])),
            network: Some("tcp"),
            ..Default::default()
        };
        black_box(router.route(&ctx));
    })
    .report();

    measure_sync("route port rule hit", &cfg, || {
        let ctx = RouteContext {
            domain: Some(black_box(&domains[1])),
            destination_port: Some(black_box(443)),
            network: Some("tcp"),
            ..Default::default()
        };
        black_box(router.route(&ctx));
    })
    .report();

    measure_sync("route final (no match)", &cfg, || {
        let ctx = RouteContext {
            domain: Some("nomatch.unknown"),
            destination_port: Some(9999),
            network: Some("udp"),
            ..Default::default()
        };
        black_box(router.route(&ctx));
    })
    .report();
}
