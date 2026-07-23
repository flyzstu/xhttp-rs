use crate::config::XmuxConfig;
use anyhow::Result;
use reqwest::Client as HttpClient;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct Pool {
    http: HttpClient,
    running: usize,
    remaining_reuse: Option<usize>,
    remaining_requests: Option<usize>,
    unusable_at: Option<Instant>,
    retired: bool,
}

struct State {
    pools: Vec<Arc<Mutex<Pool>>>,
    max_concurrency: usize,
    max_connections: usize,
}

pub(crate) struct Manager {
    config: XmuxConfig,
    build: Arc<dyn Fn() -> Result<HttpClient> + Send + Sync>,
    initial: Mutex<Option<HttpClient>>,
    state: Mutex<State>,
}

pub(crate) struct Lease {
    manager: Arc<Manager>,
    connection_pool: Arc<Mutex<Pool>>,
    request_pool: Arc<Mutex<Pool>>,
}

impl Manager {
    pub(crate) fn new(
        config: XmuxConfig,
        build: impl Fn() -> Result<HttpClient> + Send + Sync + 'static,
    ) -> Result<Arc<Self>> {
        let initial = build()?;
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                max_concurrency: config.max_concurrency.sample(),
                max_connections: config.max_connections.sample(),
                pools: Vec::new(),
            }),
            config,
            build: Arc::new(build),
            initial: Mutex::new(Some(initial)),
        }))
    }

    pub(crate) fn acquire_connection(self: &Arc<Self>) -> Result<Lease> {
        let pool = self.pick(true)?;
        {
            let mut pool = pool.lock().expect("XMUX pool lock poisoned");
            pool.running += 1;
            consume_request(&mut pool);
        }
        Ok(Lease {
            manager: self.clone(),
            connection_pool: pool.clone(),
            request_pool: pool,
        })
    }

    fn acquire_request(&self) -> Result<Arc<Mutex<Pool>>> {
        let pool = self.pick(false)?;
        consume_request(&mut pool.lock().expect("XMUX pool lock poisoned"));
        Ok(pool)
    }

    fn pick(&self, connection: bool) -> Result<Arc<Mutex<Pool>>> {
        let mut state = self.state.lock().expect("XMUX manager lock poisoned");
        let now = Instant::now();
        state.pools.retain(|entry| {
            let mut pool = entry.lock().expect("XMUX pool lock poisoned");
            if !pool.retired
                && (pool.remaining_reuse == Some(0)
                    || pool.remaining_requests == Some(0)
                    || pool.unusable_at.is_some_and(|deadline| now >= deadline))
            {
                pool.retired = true;
            }
            !(pool.retired && pool.running == 0)
        });

        let active = state
            .pools
            .iter()
            .filter(|entry| {
                let pool = entry.lock().expect("XMUX pool lock poisoned");
                !pool.retired
                    && (!connection
                        || state.max_concurrency == 0
                        || pool.running < state.max_concurrency)
            })
            .cloned()
            .collect::<Vec<_>>();
        let active_count = state
            .pools
            .iter()
            .filter(|entry| !entry.lock().expect("XMUX pool lock poisoned").retired)
            .count();

        let pool = if active.is_empty()
            || (state.max_connections > 0 && active_count < state.max_connections)
        {
            let pool = Arc::new(Mutex::new(Pool {
                http: self
                    .initial
                    .lock()
                    .expect("XMUX initial client lock poisoned")
                    .take()
                    .map(Ok)
                    .unwrap_or_else(|| (self.build)())?,
                running: 0,
                remaining_reuse: nonzero_budget(self.config.c_max_reuse_times.sample()),
                remaining_requests: nonzero_budget(self.config.h_max_request_times.sample()),
                unusable_at: nonzero_budget(self.config.h_max_reusable_secs.sample())
                    .map(|seconds| now + Duration::from_secs(seconds as u64)),
                retired: false,
            }));
            state.pools.push(pool.clone());
            pool
        } else {
            active[rand::random_range(0..active.len())].clone()
        };
        if connection {
            let mut selected = pool.lock().expect("XMUX pool lock poisoned");
            if let Some(remaining) = &mut selected.remaining_reuse {
                *remaining = remaining.saturating_sub(1);
            }
        }
        Ok(pool)
    }

    #[cfg(test)]
    fn pool_count(&self) -> usize {
        self.state
            .lock()
            .expect("XMUX manager lock poisoned")
            .pools
            .len()
    }
}

impl Lease {
    pub(crate) fn http(&self) -> HttpClient {
        self.connection_pool
            .lock()
            .expect("XMUX pool lock poisoned")
            .http
            .clone()
    }

    fn request_http(&self) -> HttpClient {
        self.request_pool
            .lock()
            .expect("XMUX pool lock poisoned")
            .http
            .clone()
    }

    pub(crate) fn http_for_packet(&mut self) -> Result<HttpClient> {
        let usable = {
            let mut pool = self.request_pool.lock().expect("XMUX pool lock poisoned");
            if pool.retired
                || pool.remaining_requests == Some(0)
                || pool
                    .unusable_at
                    .is_some_and(|deadline| Instant::now() >= deadline)
            {
                pool.retired = true;
                false
            } else {
                consume_request(&mut pool);
                true
            }
        };
        if !usable {
            self.request_pool = self.manager.acquire_request()?;
        }
        Ok(self.request_http())
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut pool = self
            .connection_pool
            .lock()
            .expect("XMUX pool lock poisoned");
        pool.running = pool.running.saturating_sub(1);
    }
}

fn nonzero_budget(value: usize) -> Option<usize> {
    (value != 0).then_some(value)
}

fn consume_request(pool: &mut Pool) {
    if let Some(remaining) = &mut pool.remaining_requests {
        *remaining = remaining.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RangeConfig;

    fn test_manager(config: XmuxConfig) -> Arc<Manager> {
        Manager::new(config, || Ok(HttpClient::new())).unwrap()
    }

    #[test]
    fn max_connections_and_reuse_budgets_rotate_pools() {
        let manager = test_manager(XmuxConfig {
            max_connections: RangeConfig { from: 4, to: 4 },
            ..Default::default()
        });
        for _ in 0..32 {
            drop(manager.acquire_connection().unwrap());
        }
        assert_eq!(manager.pool_count(), 4);

        let manager = test_manager(XmuxConfig {
            c_max_reuse_times: RangeConfig { from: 2, to: 2 },
            ..Default::default()
        });
        for _ in 0..8 {
            drop(manager.acquire_connection().unwrap());
        }
        assert_eq!(manager.pool_count(), 1);
    }

    #[test]
    fn max_concurrency_opens_additional_pools() {
        let manager = test_manager(XmuxConfig {
            max_concurrency: RangeConfig { from: 2, to: 2 },
            ..Default::default()
        });
        let leases = (0..8)
            .map(|_| manager.acquire_connection().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(manager.pool_count(), 4);
        drop(leases);
    }
}
