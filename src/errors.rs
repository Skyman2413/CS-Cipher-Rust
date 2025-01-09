use std::fmt;
use std::fmt::Formatter;

#[derive(Debug)]
pub enum CipherErrors {
    InputFileNotExistError,
    KeyFileError,
    KeyTooLongError,
    OutputPathExistsError,
}
impl fmt::Display for CipherErrors {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
