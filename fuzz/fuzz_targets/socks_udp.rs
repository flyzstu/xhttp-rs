#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xhttp::proxy::fuzz_socks_udp(data));
