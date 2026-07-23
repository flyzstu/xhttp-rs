#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

static RUNTIME: LazyLock<tokio::runtime::Runtime> =
    LazyLock::new(|| tokio::runtime::Builder::new_current_thread().build().unwrap());

fuzz_target!(|data: &[u8]| RUNTIME.block_on(xhttp::vless::fuzz_xudp_frame(data)));
