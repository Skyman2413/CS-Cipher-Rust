use std::path::PathBuf;

/// consts for round-function
const C: u64 = 0xb7e151628aed2a6a;
const CC: u64 = 0xbf7158809cf4f3c7;

/// consts to key-generating
const  CI: [u64; 9] = [
    0x290d61409ceb9e8f,
    0x1f855f585b013986,
    0x972ed7d635ae1716,
    0x21b6694ea5728708,
    0x3c18e6e7faadb889,
    0xb700f76f73841163,
    0x3f967f6ebf149dac,
    0xa40e7ef6204a6230,
    0x03c54b5a46a34465
];
pub struct Cipher {
    input_path: PathBuf,
    is_encrypt: bool,
    key_path: PathBuf,
    output_path: PathBuf,
    key: [u64; 2],
    subkeys: [u64; 9],
}

