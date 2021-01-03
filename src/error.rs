use anyhow::anyhow;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    #[error(transparent)]
    Logging(#[from] log::SetLoggerError),
}

impl From<Box<dyn std::error::Error + Send + Sync + 'static>> for Error {
    fn from(e: Box<dyn std::error::Error + Send + Sync + 'static>) -> Self {
        Self::Internal(anyhow!(e))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
