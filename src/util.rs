//! Small shared helpers reused across protocol and proxy modules.

use anyhow::{Context, Result, bail};
use std::time::Duration;

/// Parse a sing-box-style duration string (`ms`, `s`, `m`, `h` suffixes).
///
/// This is the strict form used by DNS and AnyTLS configuration; invalid or
/// unknown units are rejected rather than silently defaulted.
pub(crate) fn parse_duration(value: &str) -> Result<Duration> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, Duration::from_millis(1))
    } else if let Some(number) = value.strip_suffix('s') {
        (number, Duration::from_secs(1))
    } else if let Some(number) = value.strip_suffix('m') {
        (number, Duration::from_secs(60))
    } else if let Some(number) = value.strip_suffix('h') {
        (number, Duration::from_secs(3600))
    } else {
        bail!("invalid duration: {value}")
    };
    let count: u32 = number.parse().context("parse duration")?;
    Ok(multiplier * count)
}

/// Strict `parse_duration` with a default applied when the value is absent.
pub(crate) fn parse_duration_or(value: Option<&str>, default: Duration) -> Result<Duration> {
    value.map_or(Ok(default), parse_duration)
}

/// Lenient `parse_duration` used by route options: absent or invalid values
/// fall back to 300 milliseconds instead of failing.
pub(crate) fn parse_duration_lenient(value: Option<&str>) -> Duration {
    value
        .and_then(|value| parse_duration(value).ok())
        .unwrap_or(Duration::from_millis(300))
}

pub(crate) fn socket(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn url_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_strict_durations() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("3m").unwrap(), Duration::from_secs(180));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        for invalid in ["", "30", "1.5s", "-1s", "seconds", "1d"] {
            assert!(parse_duration(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn lenient_duration_defaults_to_300ms() {
        assert_eq!(parse_duration_lenient(None), Duration::from_millis(300));
        assert_eq!(
            parse_duration_lenient(Some("garbage")),
            Duration::from_millis(300)
        );
        assert_eq!(
            parse_duration_lenient(Some("500ms")),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn duration_or_applies_default() {
        assert_eq!(
            parse_duration_or(None, Duration::from_secs(30)).unwrap(),
            Duration::from_secs(30)
        );
        assert!(parse_duration_or(Some("1d"), Duration::from_secs(30)).is_err());
    }
}
