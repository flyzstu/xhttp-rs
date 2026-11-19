//! DNS resolver benchmarks against the real `xhttp::dns::DnsResolver`.
//! A local UDP echo server answers queries; no public network is used.

#[path = "common/mod.rs"]
mod common;

use common::{Config, Measurement, measure_async, print_header};
use std::{
    hint::black_box,
    net::{SocketAddr, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use xhttp::{
    dns::DnsResolver,
    singbox::{DnsConfig, DnsServer},
};

const CACHE_ITERATIONS: usize = 100_000;
const NETWORK_ITERATIONS: usize = 10_000;
const CONCURRENT_ITERATIONS: usize = 100_000;
const CONCURRENCY: usize = 64;

fn main() {
    let server = TestServer::start();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build benchmark runtime");
    runtime.block_on(async {
        let cfg = Config::new(1_000, CACHE_ITERATIONS, 7);
        print_header("dns resolver");

        let cached = resolver(server.address, false);
        cached
            .lookup("cached.example")
            .await
            .expect("warm lookup cache");
        measure_async("lookup cache hit", &cfg, || async {
            black_box(
                cached
                    .lookup(black_box("cached.example"))
                    .await
                    .expect("cached lookup"),
            );
        })
        .await
        .report();

        let query = build_query(1, "wire.example", 16);
        cached.exchange(&query).await.expect("warm wire cache");
        let mut id = 2u16;
        measure_async("raw exchange cache hit", &cfg, || {
            let mut query = query.clone();
            query[..2].copy_from_slice(&id.to_be_bytes());
            id = id.wrapping_add(1);
            let resolver = &cached;
            async move {
                black_box(
                    resolver
                        .exchange(&query)
                        .await
                        .expect("cached wire exchange"),
                );
            }
        })
        .await
        .report();

        let uncached = resolver(server.address, true);
        let net_cfg = Config::new(200, NETWORK_ITERATIONS, 5);
        let mut sequence = 0usize;
        measure_async("UDP multiplexed miss", &net_cfg, || {
            let query = build_query(sequence as u16, &format!("q{sequence}.example"), 16);
            sequence += 1;
            let resolver = &uncached;
            async move {
                black_box(resolver.exchange(&query).await.expect("UDP exchange"));
            }
        })
        .await
        .report();

        let concurrent = resolver(server.address, true);
        let mut samples_ns = Vec::with_capacity(7);
        for _ in 0..7 {
            let started = Instant::now();
            let mut workers = Vec::new();
            for worker in 0..CONCURRENCY {
                let resolver = concurrent.clone();
                workers.push(tokio::spawn(async move {
                    let iterations = CONCURRENT_ITERATIONS / CONCURRENCY;
                    for index in 0..iterations {
                        let sequence = worker * iterations + index;
                        let query =
                            build_query(sequence as u16, &format!("c{sequence}.example"), 16);
                        black_box(
                            resolver
                                .exchange(&query)
                                .await
                                .expect("concurrent exchange"),
                        );
                    }
                }));
            }
            for worker in workers {
                worker.await.expect("join benchmark worker");
            }
            samples_ns.push(started.elapsed().as_nanos());
        }
        Measurement {
            name: "UDP 64-way concurrent",
            iterations: CONCURRENT_ITERATIONS,
            samples_ns,
        }
        .report();
    });
}

fn resolver(address: SocketAddr, disable_cache: bool) -> DnsResolver {
    DnsResolver::new(&DnsConfig {
        servers: vec![DnsServer {
            r#type: "udp".into(),
            tag: "benchmark".into(),
            server: Some(address.ip().to_string()),
            server_port: Some(address.port()),
            path: None,
            detour: None,
        }],
        final_server: Some("benchmark".into()),
        disable_cache: Some(disable_cache),
        cache_capacity: Some(4096),
        ..Default::default()
    })
    .expect("build benchmark resolver")
}

fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(64);
    query.extend(id.to_be_bytes());
    query.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.push(0);
    query.extend(qtype.to_be_bytes());
    query.extend(1u16.to_be_bytes());
    query
}

struct TestServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl TestServer {
    fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind benchmark DNS server");
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set benchmark server timeout");
        let address = socket.local_addr().expect("benchmark server address");
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while !worker_stop.load(Ordering::Relaxed) {
                let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                if length < 12 {
                    continue;
                }
                let mut response = buffer[..length].to_vec();
                response[2] = 0x81;
                response[3] = 0x80;
                if response[6] == 0 && response[7] == 0 {
                    let qtype = u16::from_be_bytes([response[length - 4], response[length - 3]]);
                    if qtype == 1 || qtype == 28 {
                        response[7] = 1;
                        response.extend([0xc0, 0x0c]);
                        response.extend(qtype.to_be_bytes());
                        response.extend(1u16.to_be_bytes());
                        response.extend(60u32.to_be_bytes());
                        if qtype == 1 {
                            response.extend(4u16.to_be_bytes());
                            response.extend([127, 0, 0, 1]);
                        } else {
                            response.extend(16u16.to_be_bytes());
                            response.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                        }
                    }
                }
                socket
                    .send_to(&response, peer)
                    .expect("send benchmark DNS response");
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.join().expect("join benchmark DNS server");
        }
    }
}
