//! Routing benchmark for xhttp-rs
//!
//! Tests rule compilation and matching performance.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Instant;

fn main() {
    println!("============================================================");
    println!("Routing Performance Benchmark - Rust (xhttp-rs)");
    println!("============================================================");

    // Benchmark 1: Domain suffix matching
    println!("\nTest 1: Domain suffix matching");
    let iterations = 500_000;
    let suffixes = ["com", "org", "net", "io", "dev"];
    let start = Instant::now();
    for i in 0..iterations {
        let domain = format!("www{}.example.com", i % 1000);
        let _ = matches_domain_suffix(&domain, &suffixes);
    }
    let elapsed = start.elapsed();
    print_result("domain suffix match", iterations, elapsed);

    // Benchmark 2: IP CIDR matching
    println!("\nTest 2: IP CIDR matching");
    let iterations = 500_000;
    let ips: Vec<IpAddr> = (0..100)
        .map(|i| IpAddr::from_str(&format!("192.168.{}.{}", i / 256, i % 256)).unwrap())
        .collect();
    let cidrs = [
        "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap(),
        "172.16.0.0/12".parse::<ipnet::IpNet>().unwrap(),
        "192.168.0.0/16".parse::<ipnet::IpNet>().unwrap(),
    ];
    let start = Instant::now();
    for i in 0..iterations {
        let ip = ips[i % ips.len()];
        let _ = matches_ip_cidr(ip, &cidrs);
    }
    let elapsed = start.elapsed();
    print_result("IP CIDR match", iterations, elapsed);

    // Benchmark 3: Port range matching
    println!("\nTest 3: Port range matching");
    let iterations = 500_000;
    let ports: Vec<u16> = (1..=65535).step_by(7).take(1000).collect();
    let ranges: Vec<std::ops::RangeInclusive<u16>> =
        vec![80..=80, 443..=443, 8000..=9000, 10000..=11000];
    let start = Instant::now();
    for i in 0..iterations {
        let port = ports[i % ports.len()];
        let _ = matches_port_range(port, &ranges);
    }
    let elapsed = start.elapsed();
    print_result("port range match", iterations, elapsed);

    // Benchmark 4: Domain keyword matching
    println!("\nTest 4: Domain keyword matching");
    let iterations = 500_000;
    let keywords = ["ads", "tracker", "analytics", "telemetry"];
    let start = Instant::now();
    for i in 0..iterations {
        let domain = format!("www{}.example.com", i % 1000);
        let _ = matches_domain_keyword(&domain, &keywords);
    }
    let elapsed = start.elapsed();
    print_result("domain keyword match", iterations, elapsed);

    // Benchmark 5: Regex domain matching
    println!("\nTest 5: Regex domain matching");
    let iterations = 100_000;
    let pattern = regex::Regex::new(r"^.*\.(com|org|net)$").unwrap();
    let start = Instant::now();
    for i in 0..iterations {
        let domain = format!("www{}.example.com", i % 1000);
        let _ = pattern.is_match(&domain);
    }
    let elapsed = start.elapsed();
    print_result("regex domain match", iterations, elapsed);

    // Benchmark 6: Full route evaluation simulation
    println!("\nTest 6: Full route evaluation (simulated router)");
    let iterations = 200_000;
    let rules = build_simulated_rules();
    let start = Instant::now();
    for i in 0..iterations {
        let domain = format!("host{}.example.com", i % 500);
        let ip = IpAddr::from_str(&format!("10.0.{}.{}", (i / 256) % 256, i % 256)).unwrap();
        let port = ports[i % ports.len()];
        let _ = simulate_route_evaluation(&domain, ip, port, &rules);
    }
    let elapsed = start.elapsed();
    print_result("full route evaluation", iterations, elapsed);
}

fn print_result(name: &str, iterations: usize, elapsed: std::time::Duration) {
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
    let us_per_op = elapsed.as_secs_f64() * 1e6 / iterations as f64;
    println!(
        "{:28} {:>9} operations in {:>8.3}s: {:>12.0} ops/s, {:>9.2} us/op",
        name,
        iterations,
        elapsed.as_secs_f64(),
        ops_per_sec,
        us_per_op
    );
}

fn matches_domain_suffix(domain: &str, suffixes: &[&str]) -> bool {
    suffixes.iter().any(|suf| {
        domain.ends_with(suf) || domain.strip_suffix(suf).is_some_and(|r| r.ends_with('.'))
    })
}

fn matches_ip_cidr(ip: IpAddr, cidrs: &[ipnet::IpNet]) -> bool {
    cidrs.iter().any(|net| net.contains(&ip))
}

fn matches_port_range(port: u16, ranges: &[std::ops::RangeInclusive<u16>]) -> bool {
    ranges.iter().any(|r| r.contains(&port))
}

fn matches_domain_keyword(domain: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|kw| domain.contains(kw))
}

#[derive(Clone)]
enum SimulatedRule {
    DomainSuffix(String, String),                     // suffix -> outbound
    IpCidr(ipnet::IpNet, String),                     // cidr -> outbound
    PortRange(std::ops::RangeInclusive<u16>, String), // port range -> outbound
}

struct SimulatedRouter {
    rules: Vec<SimulatedRule>,
    default: String,
}

fn build_simulated_rules() -> SimulatedRouter {
    SimulatedRouter {
        rules: vec![
            SimulatedRule::DomainSuffix(".example.com".into(), "proxy".into()),
            SimulatedRule::DomainSuffix(".google.com".into(), "direct".into()),
            SimulatedRule::DomainSuffix(".github.com".into(), "proxy".into()),
            SimulatedRule::IpCidr("10.0.0.0/8".parse().unwrap(), "direct".into()),
            SimulatedRule::IpCidr("172.16.0.0/12".parse().unwrap(), "direct".into()),
            SimulatedRule::IpCidr("192.168.0.0/16".parse().unwrap(), "direct".into()),
            SimulatedRule::PortRange(80..=80, "bypass".into()),
            SimulatedRule::PortRange(443..=443, "bypass".into()),
            SimulatedRule::PortRange(8000..=9000, "proxy".into()),
        ],
        default: "direct".into(),
    }
}

fn simulate_route_evaluation<'a>(
    domain: &str,
    ip: IpAddr,
    port: u16,
    router: &'a SimulatedRouter,
) -> &'a str {
    for rule in &router.rules {
        match rule {
            SimulatedRule::DomainSuffix(suffix, outbound) => {
                if domain.ends_with(suffix) {
                    return outbound;
                }
            }
            SimulatedRule::IpCidr(cidr, outbound) => {
                if cidr.contains(&ip) {
                    return outbound;
                }
            }
            SimulatedRule::PortRange(range, outbound) => {
                if range.contains(&port) {
                    return outbound;
                }
            }
        }
    }
    &router.default
}
