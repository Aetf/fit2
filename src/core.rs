use dynomite::FromAttributes;
use envy;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDb, DynamoDbClient, PutItemInput, ScanInput};
use serde::Deserialize;

use crate::error::*;
use db::User;

pub(crate) mod db {
    use dynomite::Item;

    #[derive(Clone, Debug, Default, Item)]
    pub(crate) struct User {
        #[dynomite(partition_key)]
        pub uid: String,
        pub fitbit_access_token: String,
        pub fitbit_refresh_token: String,
        #[dynomite(default)]
        pub fitbit_oauth_csrf: Option<String>,
        #[dynomite(default)]
        pub fitbit_oauth_pkce: Option<String>,
        pub google_access_token: String,
        pub google_refresh_token: String,
        #[dynomite(default)]
        pub google_oauth_csrf: Option<String>,
        #[dynomite(default)]
        pub google_oauth_pkce: Option<String>,
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

        Ok(Fit2 {
            config,
            db,
            fitbit_oauth,
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
            .map(User::from_attrs)
            .transpose()
            .context("invalid user item, corrupted database")?;
        Ok(user)
    }

    pub(crate) async fn ensure_user(&self) -> Result<User> {
        let user = self.get_user().await?;
        let user = match user {
            Some(user) => user,
            None => {
                self.put_user(&User::new("0xdeadbeef")).await?;
                self.get_user()
                    .await?
                    .ok_or_else(|| anyhow!("User not found"))?
            }
        };
        Ok(user)
    }

    pub(crate) async fn put_user(&self, user: &User) -> Result<()> {
        let mut input = PutItemInput::default();
        input.table_name = self.config.users_table_name.clone();
        input.item = user.clone().into();
        self.db
            .put_item(input)
            .await
            .context("failed to put_user")?;
        Ok(())
    }
}

impl User {
    pub fn new(uid: impl Into<String>) -> User {
        User {
            uid: uid.into(),
            ..Default::default()
        }
    }
}
