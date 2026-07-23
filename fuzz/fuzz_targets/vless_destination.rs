#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xhttp::vless::fuzz_destination_bytes(data));
