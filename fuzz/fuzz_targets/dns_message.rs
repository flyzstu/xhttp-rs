#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xhttp::dns::fuzz_dns_message(data));
