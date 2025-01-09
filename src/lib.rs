use rand::Rng;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

mod errors;
use errors::CipherErrors;
/// consts for round-function
const C: u64 = 0xb7e151628aed2a6a;
const CC: u64 = 0xbf7158809cf4f3c7;

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
    is_encrypt: bool,
    key_path: PathBuf,
    output_path: PathBuf,
    key: [u64; 2],
    subkeys: [u64; 9],
}
impl Cipher {
    pub fn build(
        input_path: &str,
        is_encrypt: bool,
        key_path: Option<&str>,
        output_path: &str,
    ) -> Result<Cipher, CipherErrors> {
        let input_path = PathBuf::from(input_path);
        File::open(&input_path).map_err(|_| CipherErrors::InputFileNotExistError)?;
        let output_path = PathBuf::from(output_path);
        if output_path.exists() {
            return Err(CipherErrors::OutputPathExistsError);
        }
        let (key, key_path) = Cipher::extract_key(key_path, &input_path)?;
        let subkeys = Cipher::generate_subkeys(&key);
        Ok(Cipher {
            input_path,
            is_encrypt,
            key,
            key_path,
            subkeys,
            output_path,
        })
    }

    fn generate_subkeys(key: &[u64; 2]) -> [u64; 9] {
        todo!()
    }
    fn extract_key(
        key_path: Option<&str>,
        input_path: &Path,
    ) -> Result<([u64; 2], PathBuf), CipherErrors> {
        let key_path = if key_path.is_none() {
            println!(
                "Key file will be generated at file {}.key",
                input_path.display()
            );
            Self::generate_key_file(&format!("{}.key", input_path.display()))?;
            &format!("{}.key", input_path.display())
        } else {
            key_path.unwrap()
        };
        let mut key_file = File::open(key_path).map_err(|_| CipherErrors::KeyFileError)?;
        let mut key_bytes = Vec::new();
        key_file
            .read_to_end(&mut key_bytes)
            .map_err(|_| CipherErrors::KeyFileError)?;
        if key_bytes.len() > 16 {
            Err(CipherErrors::KeyTooLongError)
        } else {
            let key0 = u64::from_be_bytes(key_bytes[0..8].try_into().unwrap());
            let key1 = u64::from_be_bytes(key_bytes[8..16].try_into().unwrap());
            Ok(([key0, key1], PathBuf::from(key_path)))
        }
    }

    fn generate_key_file(path: &str) -> Result<(), CipherErrors> {
        let mut rng = rand::thread_rng();
        let key: [u8; 16] = rng.gen();
        let mut file = File::create(path).map_err(|_| CipherErrors::KeyFileError)?;
        file.write_all(&key)
            .map_err(|_| CipherErrors::KeyFileError)?;
        Ok(())
    }
}
