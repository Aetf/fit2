pub use anyhow::anyhow;
pub use anyhow::Context as _;
use thiserror::Error;
use crate::auth::OAuthRedirect;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
    #[error(transparent)]
    Logging(#[from] log::SetLoggerError),
    #[error("OAuth redirect needed")]
    AuthRedirect(OAuthRedirect),
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

impl Error {
    pub fn oauth_redirect(redirect: OAuthRedirect) -> Error {
        Error::AuthRedirect(redirect)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
