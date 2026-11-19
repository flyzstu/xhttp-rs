//! Shared benchmark harness for xhttp-rs.
//!
//! Every case does: warmup -> `samples` batches of `iterations` -> robust stats.
//! Each case prints one human-readable row plus one `BENCH_JSON {...}` line, so a
//! later run can be diffed against the committed baseline (BENCHMARK.md).
// Each benchmark binary includes this module but uses only one of the two
// measure helpers; silence the resulting per-crate dead_code warnings.
#![allow(dead_code)]

use std::time::Instant;

pub struct Config {
    pub warmup: usize,
    pub iterations: usize,
    pub samples: usize,
}

impl Config {
    pub const fn new(warmup: usize, iterations: usize, samples: usize) -> Self {
        Self {
            warmup,
            iterations,
            samples,
        }
    }
}

pub struct Measurement {
    pub name: &'static str,
    pub iterations: usize,
    pub samples_ns: Vec<u128>,
}

impl Measurement {
    fn rates(&self) -> Vec<f64> {
        let mut rates: Vec<f64> = self
            .samples_ns
            .iter()
            .map(|&ns| self.iterations as f64 / (ns as f64 / 1_000_000_000.0))
            .collect();
        rates.sort_by(f64::total_cmp);
        rates
    }

    /// Throughput from total wall time across all samples (most stable figure).
    pub fn ops_per_sec(&self) -> f64 {
        let total: u128 = self.samples_ns.iter().sum();
        (self.iterations * self.samples_ns.len()) as f64 / (total as f64 / 1_000_000_000.0)
    }

    pub fn us_per_op(&self) -> f64 {
        1_000_000.0 / self.ops_per_sec()
    }

    fn percentile(&self, rates: &[f64], fraction: f64) -> f64 {
        let rank = ((rates.len().saturating_sub(1)) as f64 * fraction).ceil() as usize;
        self.at(rates, rank)
    }

    fn at(&self, rates: &[f64], index: usize) -> f64 {
        rates[index.min(rates.len().saturating_sub(1))]
    }

    pub fn report(&self) {
        let rates = self.rates();
        let min = self.at(&rates, 0);
        let p50 = self.percentile(&rates, 0.50);
        let p95 = self.percentile(&rates, 0.95);
        let p99 = self.percentile(&rates, 0.99);
        let max = self.at(&rates, rates.len().saturating_sub(1));
        println!(
            "{:<34} {:>9} {:>13.0} {:>10.3} {:>12.0} {:>12.0} {:>12.0} {:>12.0} {:>12.0} {:>12.0}",
            self.name,
            self.iterations,
            self.ops_per_sec(),
            self.us_per_op(),
            min,
            p50,
            p95,
            p99,
            max,
            self.samples_ns.len(),
        );
        println!(
            "BENCH_JSON {{\"name\":{:?},\"iterations\":{},\"samples\":{},\"ops_per_sec\":{:.1},\"us_per_op\":{:.4},\"min_ops\":{:.1},\"p50_ops\":{:.1},\"p95_ops\":{:.1},\"p99_ops\":{:.1},\"max_ops\":{:.1}}}",
            self.name,
            self.iterations,
            self.samples_ns.len(),
            self.ops_per_sec(),
            self.us_per_op(),
            min,
            p50,
            p95,
            p99,
            max,
        );
    }
}

pub fn print_header(title: &str) {
    println!("\n=== {title} ===");
    println!(
        "{:<34} {:>9} {:>13} {:>10} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "case", "iters", "ops/s", "us/op", "min", "p50", "p95", "p99", "max", "samples"
    );
}

pub fn measure_sync<F: FnMut()>(name: &'static str, cfg: &Config, mut op: F) -> Measurement {
    for _ in 0..cfg.warmup {
        op();
    }
    let mut samples_ns = Vec::with_capacity(cfg.samples);
    for _ in 0..cfg.samples {
        let start = Instant::now();
        for _ in 0..cfg.iterations {
            op();
        }
        samples_ns.push(start.elapsed().as_nanos());
    }
    Measurement {
        name,
        iterations: cfg.iterations,
        samples_ns,
    }
}

pub async fn measure_async<F, Fut>(name: &'static str, cfg: &Config, mut op: F) -> Measurement
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    for _ in 0..cfg.warmup {
        op().await;
    }
    let mut samples_ns = Vec::with_capacity(cfg.samples);
    for _ in 0..cfg.samples {
        let start = Instant::now();
        for _ in 0..cfg.iterations {
            op().await;
        }
        samples_ns.push(start.elapsed().as_nanos());
    }
    Measurement {
        name,
        iterations: cfg.iterations,
        samples_ns,
    }
}
