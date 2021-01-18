use crate::core::{db::User, Fit2};
use crate::error::*;
use url::Url;
use chrono::{Utc, DateTime};

impl Fit2 {
    pub(crate) async fn google_oauth_redirect(&self) -> Result<Url> {
        todo!()
    }

    pub(crate) async fn google_ensure_setup(&self) -> Result<()> {
        Err(Error::from(anyhow!("google not validated")))
    }

    pub(crate) async fn google_ensure_last_sync_dt(&self) -> Result<DateTime<Utc>> {
        todo!()
    }
}

impl User {
    async fn validate_google(&self) -> Result<()> {
        Err(Error::from(anyhow!("google not validated")))
    }
}
