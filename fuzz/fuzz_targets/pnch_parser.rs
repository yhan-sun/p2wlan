#![no_main]

use libfuzzer_sys::fuzz_target;
use p2pnet_nat::{
    decode_authenticated_punch_packet, decode_punch_packet, peek_authenticated_punch_identity,
    ProbeMacKey,
};

const ZERO_KEY: ProbeMacKey = [0x00; 32];
const TEST_KEY: ProbeMacKey = [0x42; 32];
const GOLDEN_KEY: ProbeMacKey = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

fuzz_target!(|data: &[u8]| {
    // Legacy v1 parser should reject unrelated data without panicking.
    let _ = decode_punch_packet(data);

    // v2 identity peeking intentionally runs before MAC verification in the
    // daemon receive path. Keep it hardened against arbitrary network bytes.
    let _ = peek_authenticated_punch_identity(data);

    // Try representative keys used by unit tests and protocol golden vectors.
    // A successful decode is fine; the fuzzer's job is to find panics,
    // parser inconsistencies, and unexpected acceptance paths under mutation.
    for key in [ZERO_KEY, TEST_KEY, GOLDEN_KEY] {
        let _ = decode_authenticated_punch_packet(data, &key);
    }
});
