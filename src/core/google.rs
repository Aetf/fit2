use crate::core::{db::User, Fit2};
use crate::error::*;
use url::Url;

impl Fit2 {
    pub(crate) async fn google_oauth_redirect(&self) -> Result<Url> {
        todo!()
    }

    pub(crate) async fn ensure_google_token(&self) -> Result<User> {
        todo!()
    }
}

impl User {
    async fn validate_google(&self) -> Result<()> {
        Err(Error::from(anyhow!("google not validated")))
    }
}
