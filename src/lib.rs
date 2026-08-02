//! XHTTP transport compatible with the stream-one, stream-up and packet-up
//! wire formats used by Xray-core and sing-box.

pub mod anytls;
pub mod client;
pub mod config;
pub mod dns;
pub mod linux_route;
pub mod protocol;
pub mod proxy;
pub mod routing;
pub mod server;
pub mod singbox;
mod srs;
pub mod tls;
pub mod vless;
mod xmux;

pub use client::Client;
pub use config::{ClientConfig, Mode, ServerConfig, TransportConfig};
pub use server::Server;
pub use singbox::SingBoxConfig;

pub(crate) fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
