//! Windows DNS cache persistence (JSON-only).
//!
//! `bbolt-rs`'s mmap lock/unlock/advice code is Unix-only and does not compile
//! on Windows. On Windows we persist the cache as JSON instead: the same
//! snapshot format used by the Unix JSON fallback path, minus the BoltDB wire
//! format and persisted selector-group state (which depend on BoltDB buckets).
//! This keeps the DNS cache functional across restarts on Windows.

use anyhow::{Context, Result};
use std::{collections::HashMap, path::Path, sync::Mutex};

use super::cache::{DnsCache, PersistentCache};

/// Load a JSON snapshot from `path`, restoring cache entries if readable.
/// Selector-group state is not persisted on Windows, so `None` is always returned.
pub fn load_persisted(path: &Path, cache: &Mutex<DnsCache>) -> Option<HashMap<String, String>> {
    if !path.exists() {
        return None;
    }
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<PersistentCache>(&bytes) {
            Ok(snapshot) => {
                cache
                    .lock()
                    .expect("DNS cache lock poisoned")
                    .restore(snapshot);
                tracing::info!("restored DNS cache from {}", path.display());
            }
            Err(error) => tracing::warn!(
                error = %format!("{error}"),
                path = %path.display(),
                "discarding unreadable persisted DNS cache"
            ),
        },
        Err(error) => tracing::warn!(
            error = %format!("{error}"),
            path = %path.display(),
            "failed to read persisted DNS cache"
        ),
    }
    None
}

/// Save the cache as a JSON snapshot. `selected_groups` is ignored on Windows
/// because JSON snapshots do not carry selector-group state.
pub fn save_persisted(
    path: &Path,
    cache: &Mutex<DnsCache>,
    _selected_groups: Option<&HashMap<String, String>>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let snapshot = cache.lock().expect("DNS cache lock poisoned").snapshot();
    let bytes = serde_json::to_vec(&snapshot).context("serialize DNS cache snapshot")?;
    std::fs::write(path, bytes).context("write persisted DNS cache")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::cache::{CacheKey, CacheValue};
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn json_round_trip_preserves_cache_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.json");
        let cache = Mutex::new(DnsCache::new(100, false));
        cache.lock().unwrap().insert(
            CacheKey::Lookup {
                name: "example.test".into(),
                qtype: 1,
                server: None,
                client_subnet: None,
            },
            CacheValue::Addresses(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
            Duration::from_secs(300),
        );

        save_persisted(&path, &cache, None).unwrap();

        let restored = Mutex::new(DnsCache::new(100, false));
        assert!(load_persisted(&path, &restored).is_none());
        assert_eq!(restored.lock().unwrap().snapshot().entries.len(), 1);
    }
}
