use dynomite::{FromAttributes, Attributes};
use envy;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDb, DynamoDbClient, PutItemInput, ScanInput};
use serde::Deserialize;
use chrono::{Utc, DateTime};
use std::sync::Arc;
use futures::lock::Mutex;
use dynomite::Item;

use crate::auth::AuthorizationCodeFlow;
use crate::error::*;

mod db {
    use chrono::{DateTime, Utc};
    use dynomite::Item;

    #[derive(Clone, Debug, Default, Item)]
    pub struct User {
        #[dynomite(partition_key)]
        pub uid: String,

        pub fitbit_auth: String,

        #[dynomite(default)]
        pub fitbit_member_since: Option<DateTime<Utc>>,

        pub google_auth: String,

        #[dynomite(default)]
        pub google_data_source_id: Option<String>,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct User {
    db: db::User,
    fitbit_auth: Arc<Mutex<AuthorizationCodeFlow>>,
    google_auth: Arc<Mutex<AuthorizationCodeFlow>>,
}

impl db::User {
    pub(crate) async fn hydrate(self, fit2: &Fit2) -> Result<User> {
        let google_auth = serde_json::from_str(&self.google_auth)
            .context("Failed to decode json")?;
        let fitbit_auth = serde_json::from_str(&self.fitbit_auth)
            .context("Failed to decode json")?;
        Ok(User {
            db: self,
            google_auth: Arc::new(Mutex::new(AuthorizationCodeFlow::from_state(fit2.google_oauth.clone(), google_auth))),
            fitbit_auth: Arc::new(Mutex::new(AuthorizationCodeFlow::from_state(fit2.fitbit_oauth.clone(), fitbit_auth))),
        })
    }
}

impl User {
    pub fn new(uid: impl Into<String>, fit2: &Fit2) -> User {
        User {
            db: db::User {
                uid: uid.into(),
                ..Default::default()
            },
            fitbit_auth: Arc::new(Mutex::new(AuthorizationCodeFlow::new(fit2.fitbit_oauth.clone()))),
            google_auth: Arc::new(Mutex::new(AuthorizationCodeFlow::new(fit2.google_oauth.clone()))),
        }
    }

    // TODO: call this from a post-middleware
    pub(crate) async fn dehydrate(mut self) -> Result<db::User> {
        self.db.google_auth = serde_json::to_string(self.google_auth.lock().await.state())
            .context("Failed to encode JSON")?;
        self.db.fitbit_auth = serde_json::to_string(self.fitbit_auth.lock().await.state())
            .context("Failed to encode JSON")?;
        Ok(self.db)
    }

    pub fn key(&self) -> Attributes {
        self.db.key()
    }

    pub fn uid(&self) -> &String {
        &self.db.uid
    }

    pub fn google_data_source_id(&self) -> Option<&String> {
        self.db.google_data_source_id.as_ref()
    }

    pub fn fitbit_member_since(&self) -> Option<&DateTime<Utc>> {
        self.db.fitbit_member_since.as_ref()
    }

    pub fn google_auth(&self) -> &Arc<Mutex<AuthorizationCodeFlow>> {
        &self.google_auth
    }

    pub fn fitbit_auth(&self) -> &Arc<Mutex<AuthorizationCodeFlow>> {
        &self.fitbit_auth
    }
}

#[derive(Deserialize, Debug)]
struct Config {
    google_client_id: String,
    google_client_secret: String,
    fitbit_client_id: String,
    fitbit_client_secret: String,
    fitbit_subscriber_verify: String,
    users_table_name: String,
}

pub struct Fit2 {
    config: Config,
    db: DynamoDbClient,
    fitbit_oauth: BasicClient,
    google_oauth: BasicClient,
}
mod fitbit;
mod google;

impl Fit2 {
    pub fn from_env() -> Result<Fit2> {
        let config: Config = envy::from_env().context("Missing required env var")?;
        let db = DynamoDbClient::new(Region::default());
        let fitbit_oauth =
            BasicClient::new(
                ClientId::new(config.fitbit_client_id.clone()),
                Some(ClientSecret::new(config.fitbit_client_secret.clone())),
                AuthUrl::new("https://www.fitbit.com/oauth2/authorize".to_string()).expect("fitbit auth url"),
                Some(TokenUrl::new("https://api.fitbit.com/oauth2/token".to_string()).expect("fitbit token url"))
            )
                // Set the URL the user will be redirected to after the authorization process.
                .set_redirect_url(RedirectUrl::new("https://1bwjm3qs73.execute-api.us-east-1.amazonaws.com/dev/api/auth/fitbit/callback".to_string()).expect("fitbit redirect url"));
        let google_oauth = BasicClient::new(
            ClientId::new(config.google_client_id.clone()),
            Some(ClientSecret::new(config.google_client_secret.clone())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).expect("google auth url"),
            Some(TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string()).expect("google token url"))
        )
            // Set the URL the user will be redirected to after the authorization process.
            .set_redirect_url(RedirectUrl::new("https://1bwjm3qs73.execute-api.us-east-1.amazonaws.com/dev/api/auth/google/callback".to_string()).expect("google redirect url"));

        Ok(Fit2 {
            config,
            db,
            fitbit_oauth,
            google_oauth,
        })
    }

    pub(crate) async fn get_user(&self) -> Result<Option<User>> {
        let mut input = ScanInput::default();
        input.table_name = self.config.users_table_name.clone();
        input.limit = Some(1);
        let output = self.db.scan(input).await.context("failed to get user")?;
        let user = output
            .items
            .and_then(|mut items: Vec<_>| items.pop())
            .map(db::User::from_attrs)
            .transpose()
            .context("invalid user item, corrupted database")?;
        match user {
            Some(u) => {
                Ok(Some(u.hydrate(self).await?))
            },
            None => Ok(None),
        }
    }

    pub(crate) async fn ensure_user(&self) -> Result<User> {
        let user = self.get_user().await?;
        let user = match user {
            Some(user) => user,
            None => {
                self.put_user(User::new("0xdeadbeef", self)).await?;
                self.get_user()
                    .await?
                    .ok_or_else(|| anyhow!("User not found"))?
            }
        };
        Ok(user)
    }

    pub(crate) async fn put_user(&self, user: User) -> Result<()> {
        let mut input = PutItemInput::default();
        input.table_name = self.config.users_table_name.clone();
        input.item = user.clone().dehydrate().await?.into();
        self.db
            .put_item(input)
            .await
            .context("failed to put_user")?;
        Ok(())
    }

    async fn last_sync(&self) -> Result<DateTime<Utc>> {
        // max(google_max_sync, fitbit_member_since) if google_max_sync is Some(_)
        // else fitbit_member_since
        todo!("determine last sync time")
    }

    pub(crate) async fn sync_fitbit_to_google(&self) -> Result<()> {
        let begin = self.last_sync().await?;
        let points = self.fitbit_get_data_points(begin, Utc::now()).await?;

        todo!("convert points to google format and call google API to insert")
    }
}
