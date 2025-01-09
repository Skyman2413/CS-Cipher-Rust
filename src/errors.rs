use std::fmt;
use std::fmt::Formatter;

#[derive(Debug)]
pub enum CipherErrors {
    InputFileNotExist,
    KeyFile,
    KeyTooLong,
    OutputPathExists,
}
impl fmt::Display for CipherErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
