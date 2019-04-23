use super::algebra;

#[derive(Debug)]
pub enum Error {
    NotFound(String),
    AlreadyExists(String),
    Parse(String),
    InvalidParameter(String),
    InvalidSelector(String),
    BadFunctionReturn(String),
    InvalidTag(String),
    InvalidType(String),
    NotYetImplemented(String),
    Algebra(algebra::Error),
    CannotGenerateConstrain(String),
    CannotConvertToU64(algebra::FS),
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
