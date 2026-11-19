use anyhow::{Context, Result};
use bbolt_rs::{Bolt, BucketApi, BucketRwApi, CursorApi, DbApi, DbRwAPI, TxApi, TxRwRefApi};
use fs4::fs_std::FileExt;
use std::{
    collections::HashMap,
    path::Path,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::cache::{CacheKey, CacheValue, DnsCache, PersistentCache};
use super::message::parse_response;

/// Check whether the file at `path` is a BoltDB database.
pub fn is_boltdb_file(path: &Path) -> bool {
    if path.extension().and_then(|s| s.to_str()) == Some("db") {
        return true;
    }
    if let Ok(bytes) = std::fs::read(path)
        && bytes.len() >= 32
    {
        let magic = &bytes[16..20];
        return magic == [0xed, 0x0c, 0xda, 0xed]
            || magic == [0xed, 0xda, 0x0c, 0xed]
            || magic == [0x5c, 0xaf, 0xf0, 0x1d]
            || magic == [0x1d, 0xf0, 0xaf, 0x5c];
    }
    false
}

/// Load persisted DNS cache entries (and selector group state, if present in BoltDB).
pub fn load_persisted(path: &Path, cache: &Mutex<DnsCache>) -> Option<HashMap<String, String>> {
    if !path.exists() {
        return None;
    }

    // Check non-blocking lock to avoid blocking the runtime if locked by another process
    if let Ok(file) = std::fs::File::open(path) {
        if file.try_lock_shared().is_err() {
            tracing::warn!(
                path = %path.display(),
                "persisted cache file is locked by another process; skipping restore"
            );
            return None;
        }
        file.unlock().ok();
    }

    if is_boltdb_file(path) {
        match load_boltdb(path, cache) {
            Ok(selected) => Some(selected),
            Err(error) => {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    path = %path.display(),
                    "failed to read BoltDB persisted cache"
                );
                None
            }
        }
    } else {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice::<PersistentCache>(&bytes) {
                Ok(snapshot) => {
                    cache
                        .lock()
                        .expect("DNS cache lock poisoned")
                        .restore(snapshot);
                    tracing::info!("restored DNS cache from {}", path.display());
                    None
                }
                Err(error) => {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        path = %path.display(),
                        "discarding unreadable persisted DNS cache"
                    );
                    None
                }
            },
            Err(error) => {
                tracing::warn!(
                    error = %format!("{error:#}"),
                    path = %path.display(),
                    "failed to read persisted DNS cache"
                );
                None
            }
        }
    }
}

fn load_boltdb(path: &Path, cache: &Mutex<DnsCache>) -> Result<HashMap<String, String>> {
    let db = Bolt::open_ro(path).context("open BoltDB for cache restore")?;
    let mut selected_map = HashMap::new();
    let mut restored_count = 0usize;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    db.view(|tx| {
        // 1. Read selector group mappings if present
        if let Some(selected) = tx.bucket("selected") {
            let mut c = selected.cursor();
            let mut item = c.first();
            while let Some((k, Some(v))) = item {
                if let (Ok(k_str), Ok(v_str)) = (std::str::from_utf8(k), std::str::from_utf8(v)) {
                    selected_map.insert(k_str.to_owned(), v_str.to_owned());
                }
                item = c.next();
            }
        }

        // 2. Read DNS cache entries
        if let Some(dns_cache) = tx.bucket("dns_cache") {
            let mut c = dns_cache.cursor();
            let mut item = c.first();
            let mut mut_cache = cache.lock().expect("DNS cache lock poisoned");
            while let Some((sub_name, None)) = item {
                let sub_tag = std::str::from_utf8(sub_name).unwrap_or("default");
                if let Some(sub) = dns_cache.bucket(sub_name) {
                    let mut sc = sub.cursor();
                    let mut sitem = sc.first();
                    while let Some((k, Some(v))) = sitem {
                        if k.len() > 2 && v.len() >= 8 {
                            let qtype = u16::from_be_bytes([k[0], k[1]]);
                            let qname_raw = std::str::from_utf8(&k[2..]).unwrap_or_default();
                            let qname = qname_raw.trim_end_matches('.');
                            let expires_at = u64::from_be_bytes(v[..8].try_into().unwrap());
                            if expires_at > now {
                                let remaining = Duration::from_secs(expires_at - now);
                                let raw_msg = &v[8..];
                                let msg_id = if raw_msg.len() >= 2 {
                                    u16::from_be_bytes([raw_msg[0], raw_msg[1]])
                                } else {
                                    0
                                };
                                if let Ok((addresses, _ttl)) =
                                    parse_response(msg_id, qtype, raw_msg)
                                {
                                    let server = if sub_tag == "default" {
                                        None
                                    } else {
                                        Some(sub_tag.into())
                                    };
                                    mut_cache.insert(
                                        CacheKey::Lookup {
                                            name: qname.into(),
                                            qtype,
                                            server,
                                            client_subnet: None,
                                        },
                                        CacheValue::Addresses(addresses),
                                        remaining,
                                    );
                                    restored_count += 1;
                                }
                            }
                        }
                        sitem = sc.next();
                    }
                }
                item = c.next();
            }
        }
        Ok(())
    })?;

    tracing::info!(
        path = %path.display(),
        dns_entries = restored_count,
        selected_groups = selected_map.len(),
        "restored persisted cache from BoltDB"
    );
    Ok(selected_map)
}

/// Save cache entries to disk (BoltDB if `.db` or existing BoltDB file, JSON otherwise).
pub fn save_persisted(
    path: &Path,
    cache: &Mutex<DnsCache>,
    selected_groups: Option<&HashMap<String, String>>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    if is_boltdb_file(path) {
        save_boltdb(path, cache, selected_groups)
    } else {
        save_json(path, cache)
    }
}

fn save_boltdb(
    path: &Path,
    cache: &Mutex<DnsCache>,
    selected_groups: Option<&HashMap<String, String>>,
) -> Result<()> {
    if let Ok(file) = std::fs::File::open(path) {
        if file.try_lock_exclusive().is_err() {
            tracing::debug!(
                path = %path.display(),
                "persisted cache file is locked by another process; skipping save"
            );
            return Ok(());
        }
        file.unlock().ok();
    }

    let mut db = Bolt::open(path).context("open BoltDB for cache saving")?;
    let snapshot = cache.lock().expect("DNS cache lock poisoned").snapshot();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    db.update(|mut tx| {
        // 1. Save selected groups
        if let Some(groups) = selected_groups {
            let mut sel_b = tx.create_bucket_if_not_exists("selected")?;
            for (group, selected) in groups.iter() {
                sel_b.put(group.as_bytes(), selected.as_bytes())?;
            }
        }

        // 2. Save DNS entries
        let mut root_b = tx.create_bucket_if_not_exists("dns_cache")?;
        for entry in &snapshot.entries {
            if entry.expires_at <= now {
                continue;
            }
            let (qtype, name, server, addresses, wire_opt) = match (&entry.key, &entry.value) {
                (
                    super::cache::PersistentKey::Lookup {
                        name,
                        qtype,
                        server,
                        ..
                    },
                    super::cache::PersistentValue::Addresses(addresses),
                ) => (
                    *qtype,
                    std::borrow::Cow::Borrowed(name.as_str()),
                    server.as_deref(),
                    addresses.as_slice(),
                    None,
                ),
                (
                    super::cache::PersistentKey::Wire { query, server },
                    super::cache::PersistentValue::Wire(wire),
                ) => {
                    if let Ok((name, qtype, _)) = super::message::parse_question(query) {
                        (
                            qtype,
                            std::borrow::Cow::Owned(name),
                            Some(server.as_str()),
                            &[][..],
                            Some(wire.as_slice()),
                        )
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            let sub_name = server.unwrap_or("dns_local");
            let mut sub_b = root_b.create_bucket_if_not_exists(sub_name.as_bytes())?;

            let mut key = Vec::with_capacity(2 + name.len() + 1);
            key.extend_from_slice(&qtype.to_be_bytes());
            key.extend_from_slice(name.as_bytes());
            if !name.ends_with('.') {
                key.push(b'.');
            }

            let ttl = entry.expires_at.saturating_sub(now).min(u32::MAX as u64) as u32;
            let wire_bytes: std::borrow::Cow<'_, [u8]> = if let Some(wire) = wire_opt {
                std::borrow::Cow::Borrowed(wire)
            } else if let Ok(built) = super::message::build_response(&name, qtype, addresses, ttl) {
                std::borrow::Cow::Owned(built)
            } else {
                continue;
            };

            let mut val = Vec::with_capacity(8 + wire_bytes.len());
            val.extend_from_slice(&entry.expires_at.to_be_bytes());
            val.extend_from_slice(&wire_bytes);

            sub_b.put(&key, val)?;
        }
        Ok(())
    })?;

    Ok(())
}

fn save_json(path: &Path, cache: &Mutex<DnsCache>) -> Result<()> {
    let snapshot = cache.lock().expect("DNS cache lock poisoned").snapshot();
    let bytes = serde_json::to_vec(&snapshot).context("serialize DNS cache snapshot")?;
    std::fs::write(path, bytes).context("write persisted DNS cache")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_boltdb_save_and_restore_round_trip() {
        let tmp = tempfile::Builder::new().suffix(".db").tempfile().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp); // remove file so Bolt creates cleanly

        let cache = Mutex::new(DnsCache::new(100, false));
        {
            let mut c = cache.lock().unwrap();
            c.insert(
                CacheKey::Lookup {
                    name: "example.com".into(),
                    qtype: 1,
                    server: Some("dns_local".into()),
                    client_subnet: None,
                },
                CacheValue::Addresses(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
                Duration::from_secs(300),
            );
        }

        let mut selected = HashMap::new();
        selected.insert("proxy".into(), "anytls".into());
        selected.insert("anytls".into(), "aliyunsg-anytls".into());

        save_persisted(&path, &cache, Some(&selected)).unwrap();
        assert!(is_boltdb_file(&path));

        let restored_cache = Mutex::new(DnsCache::new(100, false));
        let restored_selected = load_persisted(&path, &restored_cache).unwrap();

        assert_eq!(
            restored_selected.get("proxy").map(|s| s.as_str()),
            Some("anytls")
        );
        assert_eq!(
            restored_selected.get("anytls").map(|s| s.as_str()),
            Some("aliyunsg-anytls")
        );

        let mut c = restored_cache.lock().unwrap();
        let entry = c.get(&CacheKey::Lookup {
            name: "example.com".into(),
            qtype: 1,
            server: Some("dns_local".into()),
            client_subnet: None,
        });
        assert!(entry.is_some());
        if let Some(CacheValue::Addresses(addrs)) = entry {
            assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        } else {
            panic!("expected addresses");
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_is_boltdb_file_detection() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        assert!(!is_boltdb_file(tmp.path()));

        let db_tmp = tempfile::Builder::new().suffix(".db").tempfile().unwrap();
        assert!(is_boltdb_file(db_tmp.path()));

        // Magic byte detection
        let mut magic_bytes = vec![0u8; 32];
        magic_bytes[16..20].copy_from_slice(&[0xed, 0x0c, 0xda, 0xed]);
        let bin_tmp = tempfile::Builder::new().suffix(".dat").tempfile().unwrap();
        std::fs::write(bin_tmp.path(), &magic_bytes).unwrap();
        assert!(is_boltdb_file(bin_tmp.path()));
    }

    #[test]
    fn test_boltdb_wire_round_trip() {
        let tmp = tempfile::Builder::new().suffix(".db").tempfile().unwrap();
        let path = tmp.path().to_path_buf();
        drop(tmp);

        let mut query = vec![0u8; 12];
        query[5] = 1; // QDCOUNT = 1
        for label in "rust-lang.org".split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());

        let wire_response = super::super::message::build_response(
            "rust-lang.org",
            1,
            &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            300,
        )
        .unwrap();

        let cache = Mutex::new(DnsCache::new(100, false));
        {
            let mut c = cache.lock().unwrap();
            c.insert(
                CacheKey::Wire {
                    query: query.clone().into(),
                    server: "dns_proxy".into(),
                },
                CacheValue::Wire(wire_response.clone()),
                Duration::from_secs(300),
            );
        }

        save_persisted(&path, &cache, None).unwrap();

        let restored_cache = Mutex::new(DnsCache::new(100, false));
        load_persisted(&path, &restored_cache);

        let mut c = restored_cache.lock().unwrap();
        let entry = c.get(&CacheKey::Lookup {
            name: "rust-lang.org".into(),
            qtype: 1,
            server: Some("dns_proxy".into()),
            client_subnet: None,
        });
        assert!(entry.is_some());
        if let Some(CacheValue::Addresses(addrs)) = entry {
            assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        } else {
            panic!("expected addresses");
        }

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_save_skips_when_file_is_locked() {
        use fs4::fs_std::FileExt;
        let tmp = tempfile::Builder::new().suffix(".db").tempfile().unwrap();
        let path = tmp.path().to_path_buf();

        let file = std::fs::File::create(&path).unwrap();
        file.lock_exclusive().unwrap();

        let cache = Mutex::new(DnsCache::new(100, false));
        // Must return Ok(()) without deadlock
        let result = save_persisted(&path, &cache, None);
        assert!(result.is_ok());

        file.unlock().unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_read_existing_singbox_cache_copy() {
        let path = Path::new("/tmp/cache_copy.db");
        if path.exists() {
            let cache = Mutex::new(DnsCache::new(100, false));
            let selected = load_persisted(path, &cache);
            assert!(selected.is_some());
            let sel = selected.unwrap();
            assert!(sel.contains_key("anytls"));
        }
    }
}
