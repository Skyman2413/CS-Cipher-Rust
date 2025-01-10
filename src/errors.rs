use std::fmt;
use std::fmt::Formatter;
use std::io::Error;

#[derive(Debug)]
pub enum CipherErrors {
    InputFile(Error),
    KeyFile(Error),
    KeyTooLong,
    OutputPathExists,
}
impl fmt::Display for CipherErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
