#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xhttp::protocol::fuzz_metadata(data));
