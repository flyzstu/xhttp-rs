//! Windows system proxy integration (WinINet per-connection options).
//!
//! Mirrors xhttp-box's `tun.platform.http_proxy` behaviour: writes the proxy
//! into the current user's WinINet settings via `InternetSetOptionW`, then
//! broadcasts the settings-changed notifications. It does not intercept
//! traffic by itself — only applications that honour the Windows system proxy
//! setting are affected. On non-Windows platforms enabling it is an error so a
//! misconfigured shared config cannot silently do nothing.

use anyhow::Result;

/// Build the `http://host:port` proxy string passed to WinINet.
fn proxy_url(server: &str, server_port: u16) -> String {
    format!("http://{server}:{server_port}")
}

/// WinINet expects a semicolon-separated bypass list.
fn bypass_string(bypass: &[String]) -> String {
    bypass.join(";")
}

/// Guard for an active system-proxy setting. Dropping it restores the previous
/// (direct + auto-detect) setting, including on early-return error paths.
pub struct SystemProxy {
    active: bool,
}

impl SystemProxy {
    /// Set the system proxy. Returns a guard that clears it on drop.
    pub fn enable(server: &str, server_port: u16, bypass: &[String]) -> Result<Self> {
        let url = proxy_url(server, server_port);
        platform::set_system_proxy(&url, &bypass_string(bypass))?;
        Ok(Self { active: true })
    }

    /// Restore direct + auto-detect. Idempotent.
    pub fn disable(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        platform::clear_system_proxy()?;
        self.active = false;
        Ok(())
    }
}

impl Drop for SystemProxy {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.disable()
        {
            tracing::warn!(
                error = %format!("{error:#}"),
                "failed to restore system proxy on shutdown"
            );
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    use anyhow::{Result, bail};
    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_OPTION_PER_CONNECTION_OPTION, INTERNET_OPTION_PROXY_SETTINGS_CHANGED,
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_FLAGS,
        INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTIONW_0,
        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, InternetSetOptionW,
        PROXY_TYPE_AUTO_DETECT, PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY,
    };

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn set_option(option: u32, buffer: *const c_void, length: u32) -> Result<()> {
        // SAFETY: `buffer` either points to a live `INTERNET_PER_CONN_OPTION_LISTW`
        // in `apply_options` for the whole call, or is null for the notification
        // options that take no buffer. `length` matches the pointed-to struct.
        let ok = unsafe { InternetSetOptionW(std::ptr::null(), option, buffer, length) };
        if ok == 0 {
            bail!(
                "InternetSetOptionW({option}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    fn apply_options(options: &mut [INTERNET_PER_CONN_OPTIONW]) -> Result<()> {
        let list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: std::ptr::null_mut(),
            dwOptionCount: options.len() as u32,
            dwOptionError: 0,
            pOptions: options.as_mut_ptr(),
        };
        set_option(
            INTERNET_OPTION_PER_CONNECTION_OPTION,
            &list as *const _ as *const c_void,
            list.dwSize,
        )?;
        set_option(INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0)?;
        set_option(INTERNET_OPTION_PROXY_SETTINGS_CHANGED, std::ptr::null(), 0)?;
        set_option(INTERNET_OPTION_REFRESH, std::ptr::null(), 0)
    }

    fn flag(value: u32) -> INTERNET_PER_CONN_OPTIONW {
        INTERNET_PER_CONN_OPTIONW {
            dwOption: INTERNET_PER_CONN_FLAGS,
            Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: value },
        }
    }

    pub(super) fn set_system_proxy(proxy: &str, bypass: &str) -> Result<()> {
        // These buffers must outlive `apply_options` (WinINet keeps the
        // pointers only for the duration of the call, which copies the data).
        let mut proxy = wide(proxy);
        let mut bypass = wide(bypass);
        let mut options = vec![
            flag(PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT),
            INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_SERVER,
                Value: INTERNET_PER_CONN_OPTIONW_0 {
                    pszValue: proxy.as_mut_ptr(),
                },
            },
        ];
        if bypass.len() > 1 {
            options.push(INTERNET_PER_CONN_OPTIONW {
                dwOption: INTERNET_PER_CONN_PROXY_BYPASS,
                Value: INTERNET_PER_CONN_OPTIONW_0 {
                    pszValue: bypass.as_mut_ptr(),
                },
            });
        }
        apply_options(&mut options)
    }

    pub(super) fn clear_system_proxy() -> Result<()> {
        let mut options = [flag(PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT)];
        apply_options(&mut options)
    }
}

#[cfg(not(windows))]
mod platform {
    use anyhow::{Result, bail};

    pub(super) fn set_system_proxy(_proxy: &str, _bypass: &str) -> Result<()> {
        bail!("system_proxy is only supported on Windows")
    }

    pub(super) fn clear_system_proxy() -> Result<()> {
        bail!("system_proxy is only supported on Windows")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_url_uses_http_scheme() {
        assert_eq!(proxy_url("127.0.0.1", 7890), "http://127.0.0.1:7890");
        assert_eq!(proxy_url("proxy.local", 1080), "http://proxy.local:1080");
    }

    #[test]
    fn bypass_string_is_semicolon_separated() {
        let bypass = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        assert_eq!(bypass_string(&bypass), "localhost;127.0.0.1");
        assert_eq!(bypass_string(&[]), "");
    }

    #[cfg(windows)]
    #[test]
    fn wininet_option_layout_matches_abi() {
        use windows_sys::Win32::Networking::WinInet::{
            INTERNET_PER_CONN_OPTION_LISTW, INTERNET_PER_CONN_OPTIONW,
        };
        // The union's widest member is 8 bytes (FILETIME / pointer), and on
        // x64 it is 8-byte aligned, so dwOption is followed by 4 bytes of pad.
        assert_eq!(std::mem::align_of::<INTERNET_PER_CONN_OPTIONW>(), 8);
        assert_eq!(std::mem::align_of::<INTERNET_PER_CONN_OPTION_LISTW>(), 8);
        assert_eq!(
            std::mem::offset_of!(INTERNET_PER_CONN_OPTION_LISTW, pOptions),
            24
        );
    }
}
