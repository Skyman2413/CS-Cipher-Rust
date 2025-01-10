use rand::Rng;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use crate::errors::CipherErrors;

/// consts for round-function
const C: [u8; 8] = [0xb7, 0xe1, 0x51, 0x62, 0x8a, 0xed, 0x2a, 0x6a];
const CC: [u8; 8] = [0xbf, 0x71, 0x58, 0x80, 0x9c, 0xf4, 0xf3, 0xc7];

/// consts to key-generating
const CI: [u64; 9] = [
    0x290d61409ceb9e8f,
    0x1f855f585b013986,
    0x972ed7d635ae1716,
    0x21b6694ea5728708,
    0x3c18e6e7faadb889,
    0xb700f76f73841163,
    0x3f967f6ebf149dac,
    0xa40e7ef6204a6230,
    0x03c54b5a46a34465,
];

pub struct Cipher {
    input_path: PathBuf,
    is_encrypted: bool,
    key_path: PathBuf,
    output_path: PathBuf,
    key: [u64; 2],
    subkeys: [u64; 9],
}

trait Encrypt {
    type Error;
    fn encrypt(&mut self) -> Result<(), Self::Error>;
}
trait Decrypt {
    type Error;
    fn decrypt(&mut self) -> Result<(), Self::Error>;
}
impl Cipher {
    pub fn build(
        input_path: &PathBuf,
        is_encrypted: bool,
        key_path: &Option<PathBuf>,
        output_path: &PathBuf,
    ) -> Result<Cipher, CipherErrors> {
        File::open(input_path).map_err(CipherErrors::InputFile)?;
        if output_path.exists() {
            return Err(CipherErrors::OutputPathExists);
        }
        let (key, key_path) = Cipher::extract_key(key_path, input_path)?;
        let subkeys = Cipher::generate_subkeys(&key);
        Ok(Cipher {
            input_path: input_path.clone(),
            is_encrypted,
            key,
            key_path,
            subkeys,
            output_path: output_path.clone(),
        })
    }
    fn extract_key(
        key_path: &Option<PathBuf>,
        input_path: &Path,
    ) -> Result<([u64; 2], PathBuf), CipherErrors> {
        let key_path = if key_path.is_none() {
            println!(
                "Key file will be generated at file {}.key",
                input_path.display()
            );
            Self::generate_key_file(&format!("{}.key", input_path.display()))?;
            PathBuf::from(&format!("{}.key", input_path.display()))
        } else {
            key_path.clone().unwrap()
        };
        let mut key_file = File::open(&key_path).map_err(CipherErrors::KeyFile)?;
        let mut key_bytes = Vec::new();
        key_file
            .read_to_end(&mut key_bytes)
            .map_err(CipherErrors::KeyFile)?;
        if key_bytes.len() > 16 {
            Err(CipherErrors::KeyTooLong)
        } else {
            if key_bytes.len() < 16 {
                let padding_size = 16 - key_bytes.len();
                let padding = vec![0; padding_size];
                key_bytes.extend_from_slice(&padding);
            }
            let key0 = u64::from_be_bytes(key_bytes[0..8].try_into().unwrap());
            let key1 = u64::from_be_bytes(key_bytes[8..16].try_into().unwrap());
            Ok(([key0, key1], PathBuf::from(&key_path)))
        }
    }
}
impl Cipher {
    fn generate_key_file(path: &str) -> Result<(), CipherErrors> {
        let mut rng = rand::thread_rng();
        let key: [u8; 16] = rng.gen();
        let mut file = File::create(path).map_err(CipherErrors::KeyFile)?;
        file.write_all(&key)
            .map_err(CipherErrors::KeyFile)?;
        Ok(())
    }

    fn generate_subkeys(key: &[u64; 2]) -> [u64; 9] {
        // k-2, k-1
        let (k_1, k_2) = (key[0], key[1]);
        let mut subkeys: [u64; 9] = [0; 9];
        for i in 0..subkeys.len() {
            if i == 0 {
                let k_1c = k_1 ^ CI[i];
                let p8 = Self::p8(k_1c);
                let t = Self::t(&p8);
                subkeys[i] = k_2 ^ t;
            } else if i == 1 {
                subkeys[i] = k_1 ^ Self::t(&Self::p8(subkeys[i - 1] ^ CI[i]));
            } else {
                subkeys[i] = subkeys[i - 2] ^ Self::t(&Self::p8(subkeys[i - 1] ^ CI[i]));
            }
        }
        subkeys
    }
}
impl Cipher {
    const F: [u8; 16] = [
        0xF, 0xD, 0xB, 0xB, 0x7, 0x5, 0x7, 0x7, 0xE, 0xD, 0xA, 0xB, 0xE, 0xD, 0xE, 0xF,
    ];
    const G: [u8; 16] = [
        0xA, 0x6, 0x0, 0x2, 0xB, 0xE, 0x1, 0x8, 0xD, 0x4, 0x5, 0x3, 0xF, 0xC, 0x7, 0x9,
    ];

    fn slice_xor(a: &[u8], b: &[u8]) -> [u8; 8] {
        if a.len() != b.len() {
            unreachable!();
        };
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x ^ y)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
    /// Use Self:: p func to chunk (8 bytes)
    fn p8(arg: u64) -> [u8; 8] {
        let bytes: [u8; 8] = arg.to_be_bytes();
        let bytes: [u8; 8] = bytes
            .iter()
            .map(|n| Self::p(*n))
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        bytes
    }
    fn t(bytes: &[u8; 8]) -> u64 {
        let result: [u8; 8] = (0..8)
            .map(|i| {
                bytes
                    .iter()
                    .fold(0u8, |acc, &byte| acc << 1 | ((byte >> (7 - i)) & 0x1))
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        u64::from_be_bytes(result)
    }

    fn p(arg: u8) -> u8 {
        let (pl, pr) = ((arg >> 4) & 0xF, arg & 0xF);
        let t = pl ^ Self::F[pr as usize];
        let qr = pr ^ Self::G[t as usize];
        let ql = t ^ Self::F[qr as usize];

        (ql << 4) | (qr & 0x0F)
    }
}

impl Cipher {
    fn phi(input: u8) -> u8 {
        (input.rotate_left(1) & 0xAA) ^ input
    }
    fn m(arg: &[u8; 2]) -> [u8; 2] {
        let (xl, xr): (u8, u8) = (arg[0], arg[1]);
        let yl = Self::p(Self::phi(xl) ^ xr);
        let yr = Self::p(xl.rotate_left(1) ^ xr);
        [yl, yr]
    }
    /// Using Self::m to data-chunk (8 bytes)
    fn m8(data: [u8; 8]) -> [u8; 8] {
        let mut res: [u8; 8] = [0; 8];
        data.chunks(2).enumerate().for_each(|(i, chunk)| {
            let pair: [u8; 2] = Self::m(<&[u8; 2]>::try_from(&chunk[0..2]).unwrap());
            res[i * 2] = pair[0];
            res[i * 2 + 1] = pair[1];
        });
        res
    }
    fn r(data: u64) -> u64 {
        let t2 = Self::m8(data.to_be_bytes());
        println!("t3 = {:x}", u64::from_be_bytes(t2));
        let t4 = Self::slice_xor(&t2, &C);
        let t5: [u8; 8] = Self::m8(t4);
        println!("t6 = {:x}", u64::from_be_bytes(t5));
        let t7 = Self::slice_xor(&t5, &CC);
        u64::from_be_bytes(t7)
    }
}
impl Decrypt for Cipher {
    type Error = CipherErrors;

    fn decrypt(&mut self) -> Result<(), CipherErrors> {
        Ok(())
    }
}

impl Encrypt for Cipher {
    type Error = CipherErrors;

    fn encrypt(&mut self) -> Result<(), CipherErrors> {
        let mut file = File::open(&self.input_path).map_err(CipherErrors::InputFile)?;
        let mut buffer = [0u8; 8];
        
        loop {
            let bytes_read = file.read(&mut buffer).map_err(CipherErrors::InputFile)?;
            if bytes_read == 0 {
                break;
            }
            println!("{:x}", u64::from_be_bytes(buffer));
            let m1 = Self::r(self.subkeys[0] ^ u64::from_be_bytes(buffer));
            let m2 = Self::r(self.subkeys[1] ^ m1);
            let m3 = Self::r(self.subkeys[2] ^ m2);
            let m4 = Self::r(self.subkeys[3] ^ m3);
            let m5 = Self::r(self.subkeys[4] ^ m4);
            let m6 = Self::r(self.subkeys[5] ^ m5);
            let m7 = Self::r(self.subkeys[6] ^ m6);
            let s = self.subkeys[7] ^ m7;
            println!("{:x}", m1);
            println!("{:x}", m2);
            println!("{:x}", m3);
            println!("{:x}", m4);
            println!("{:x}", m5);
            println!("{:x}", m6);
            println!("{:x}", m7);
            println!("{:x}", s);;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn cipher_encrypt() {
        let mut cipher = Cipher::build(
            &PathBuf::from("./test/encrypt/input".to_string()),
            false,
            &Some(PathBuf::from("./test/encrypt/key")),
            &PathBuf::from("./test/encrypt/output".to_string()),
        ).unwrap();
        cipher.encrypt().unwrap();
        
    }
    #[test]
    fn p8_func() {
        let a = Cipher::p8(0x0123456789abcdef);
        assert_eq!(u64::from_be_bytes(a), 0x0de7a3c127cdabc9);
    }

    #[test]
    fn p_func() {
        let n = 0x26_u8;
        assert_eq!(Cipher::p(n), 0xb8);
        assert_eq!(Cipher::p(0xEC), 0x76)
    }

    #[test]
    fn t_func() {
        let a: u64 = 0b0001001010111011110010101001101010010001001101000011011110001110;
        let b: u64 = 0b0111100100100000010001101101111001110001000001111111001101001010;

        assert_eq!(Cipher::t(&a.to_be_bytes()), b);
    }

    #[test]
    fn generate_key() {
        let key_bytes = 0x0123456789abcdeffedcba9876543210_u128.to_be_bytes();
        let key0 = u64::from_be_bytes(key_bytes[0..8].try_into().unwrap());
        let key1 = u64::from_be_bytes(key_bytes[8..16].try_into().unwrap());
        assert_eq!(
            Cipher::generate_subkeys(&[key0, key1]),
            [
                0x45fd137a4edf9ec4,
                0x1dd43f03e6f7564c,
                0xebe26756de9937c7,
                0x961704e945bad4fb,
                0x0b60dfe9eff473d4,
                0x76d3e7cf52c466cf,
                0x75ec8cef767d3a0d,
                0x82da3337b598fd6d,
                0xfbd820da8dc8af8c,
            ]
        );
    }
}
