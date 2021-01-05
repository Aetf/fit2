use thiserror::Error;
pub use anyhow::anyhow;
pub use anyhow::Context as _;

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

impl From<routerify::Error> for Error {
    fn from(e: routerify::Error) -> Self {
        Self::Internal(anyhow!(e))
    }
}

impl From<hyper::Error> for Error {
    fn from(e: hyper::Error) -> Self {
        Self::Internal(anyhow!(e))
    }
}

impl From<lambda_http::http::Error> for Error {
    fn from(e: lambda_http::http::Error) -> Self {
        Self::Internal(anyhow!(e))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
