use crate::error::*;
use dynomite::{attr_map, FromAttributes, Item};
use envy;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::url::Url;
use oauth2::{AsyncCodeTokenRequest, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl, RefreshToken, AsyncRefreshTokenRequest};
use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDb, DynamoDbClient, PutItemInput, ScanInput, UpdateItemInput};
use serde::Deserialize;

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
use db::User;

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
}

impl Fit2 {
    pub fn from_env() -> Result<Fit2> {
        let config = envy::from_env().context("Missing required env var")?;
        let db = DynamoDbClient::new(Region::default());

        Ok(Fit2 { config, db })
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
                self.put_user(&User::new("")).await?;
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

    fn fitbit_oauth(&self) -> Result<BasicClient> {
        // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
        // token URL.
        let client =
            BasicClient::new(
                ClientId::new(self.config.fitbit_client_id.clone()),
                Some(ClientSecret::new(self.config.fitbit_client_secret.clone())),
                AuthUrl::new("https://www.fitbit.com/oauth2/authorize".to_string()).expect("fitbit auth url"),
                Some(TokenUrl::new("https://api.fitbit.com/oauth2/token".to_string()).expect("fitbit token url"))
            )
                // Set the URL the user will be redirected to after the authorization process.
                .set_redirect_url(RedirectUrl::new("https://1bwjm3qs73.execute-api.us-east-1.amazonaws.com/dev/api/auth/fitbit/callback".to_string()).expect("fitbit redirect url"));
        Ok(client)
    }

    pub(crate) async fn google_oauth_redirect(&self) -> Result<Url> {
        todo!()
    }

    pub(crate) async fn fitbit_oauth_redirect(&self) -> Result<Url> {
        let client = self.fitbit_oauth()?;
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        // Generate the full authorization URL.
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            // Set the desired scopes.
            .add_scope(Scope::new("weight".to_string()))
            .url();

        let mut user = self.ensure_user().await?;
        user.fitbit_oauth_csrf = Some(csrf_token.secret().clone());
        user.fitbit_oauth_pkce = Some(pkce_verifier.secret().clone());
        self.update_fitbit_oauth(user).await?;

        Ok(auth_url)
    }

    pub(crate) async fn fitbit_oauth_token(
        &self,
        csrf: impl AsRef<str>,
        code: impl Into<String>,
    ) -> Result<User> {
        let csrf = csrf.as_ref();
        let code = code.into();

        // check csrf
        let user = self.ensure_user().await?;
        if user.fitbit_oauth_csrf.as_deref() != Some(csrf) {
            return Err(anyhow!(
                "Fitbit csrf mismatch: got {} expected {:?}",
                csrf,
                &user.fitbit_oauth_csrf
            )
            .into());
        }

        let pkce_verifier = user
            .fitbit_oauth_pkce
            .clone()
            .ok_or_else(|| anyhow!("Missing Fitbit pkce verifier"))?;

        let client = self.fitbit_oauth()?;
        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(async_http_client)
            .await
            .map_err(|e| anyhow!(format!("{:?}", e)))?;

        let refresh = token
            .refresh_token()
            .ok_or_else(|| anyhow!("Missing Fitbit refresh token"))?
            .secret()
            .clone();
        let token = token.access_token().secret().clone();
        let user = self.update_fitbit_token(user, token, refresh).await?;
        Ok(user)
    }

    async fn update_fitbit_oauth(&self, user: User) -> Result<User> {
        let input = UpdateItemInput {
            key: user.key(),
            return_values: Some("ALL_NEW".to_owned()),
            table_name: self.config.users_table_name.clone(),
            update_expression: Some(
                "SET fitbit_oauth_csrf = :csrf, fitbit_oauth_pkce = :pkce".to_owned(),
            ),
            expression_attribute_values: Some(attr_map! {
                ":csrf" => user.fitbit_oauth_csrf.unwrap_or_default(),
                ":pkce" => user.fitbit_oauth_pkce.unwrap_or_default(),
            }),
            ..Default::default()
        };
        let output = self
            .db
            .update_item(input)
            .await
            .context("update fitbit oauth state")?;
        let user = User::from_attrs(output.attributes.unwrap_or_default())
            .context("update fitbit oauth state")?;
        Ok(user)
    }

    async fn update_fitbit_token(
        &self,
        user: User,
        token: String,
        refresh: String,
    ) -> Result<User> {
        // update fitbit subscription
        {
            let client = reqwest::Client::new();
            client.delete(&format!("https://api.fitbit.com/1/user/-/body/apiSubscriptions/{}.json", &user.uid))
                .bearer_auth(&user.fitbit_access_token)
                .send()
                .await
                .context("fitbit delete subscribe")?;
            client
                .post(&format!("https://api.fitbit.com/1/user/-/body/apiSubscriptions/{}.json", &user.uid))
                .bearer_auth(&user.fitbit_access_token)
                .send()
                .await
                .context("fitbit subscribe")?
                .error_for_status()
                .context("fitbit subscribe")?;
        }

        let input = UpdateItemInput {
            key: user.key(),
            return_values: Some("ALL_NEW".to_owned()),
            table_name: self.config.users_table_name.clone(),
            update_expression: Some("SET fitbit_access_token = :token, fitbit_refresh_token = :refresh REMOVE fitbit_oauth_csrf, fitbit_oauth_pkce".to_owned()),
            expression_attribute_values: Some(attr_map!{
                ":token" => token,
                ":refresh" => refresh,
            }),
            .. Default::default()
        };
        let output = self
            .db
            .update_item(input)
            .await
            .context("update fitbit oauth token")?;
        let user = User::from_attrs(output.attributes.unwrap_or_default())
            .context("update fitbit oauth token")?;
        Ok(user)
    }

    pub(crate) async fn ensure_fitbit_token(&self) -> Result<()> {
        let user = self.ensure_user().await?;
        if let Ok(_) = user.validate_fitbit().await {
            return Ok(());
        }
        let client = self.fitbit_oauth()?;
        let token = client.exchange_refresh_token(&RefreshToken::new(user.fitbit_refresh_token.clone()))
            .request_async(async_http_client)
            .await
            .map_err(|e| anyhow!(format!("{:?}", e)))?;
        let refresh = token
            .refresh_token()
            .ok_or_else(|| anyhow!("Missing Fitbit refresh token"))?
            .secret()
            .clone();
        let token = token.access_token().secret().clone();
        self.update_fitbit_token(user, token, refresh).await?;
        Ok(())
    }

    pub(crate) async fn ensure_google_token(&self) -> Result<User> {
        todo!()
    }

    async fn update_google_oauth(&mut self, csrf: CsrfToken, pkce: PkceCodeVerifier) -> Result<()> {
        todo!()
    }

    pub(crate) async fn fitbit_sub_verify(&self, verify: Option<impl AsRef<str>>) -> Result<()> {
        let verify = verify.as_ref().map(|s| s.as_ref());
        if verify == Some(&self.config.fitbit_subscriber_verify) {
            Ok(())
        } else {
            Err(anyhow!("invalid subscriber verify: {:?}", verify).into())
        }
    }
}

impl User {
    pub fn new(uid: impl Into<String>) -> User {
        User {
            uid: uid.into(),
            ..Default::default()
        }
    }

    async fn validate_fitbit(&self) -> Result<()> {
        /*
        // access token is correct
        let body: serde_json::Value = reqwest::Client::new()
            .post("https://api.fitbit.com/1.1/oauth2/introspect")
            .bearer_auth(&self.fitbit_access_token)
            .form(&[("token", &self.fitbit_access_token)])
            .send()
            .await
            .context("fitbit oauth token introspect")?
            .json()
            .await
            .context("fitbit oauth token introspect")?;
        if !body["active"].as_bool().unwrap_or(false) {
            return Err(anyhow!("inactive token").into());
        }
         */
        // subscription is setup
        let body: serde_json::Value = reqwest::Client::new()
            .get("https://api.fitbit.com/1/user/-/body/apiSubscriptions.json")
            .bearer_auth(&self.fitbit_access_token)
            .send()
            .await
            .context("fitbit validate get subscriptions list")?
            .json()
            .await
            .context("fitbit validate get subscriptions list to json")?;

        if body["apiSubscriptions"][0]["subscriptionId"].as_str() != Some(&self.uid) {
            return Err(anyhow!("no fitbit subscription setup").into());
        }

        Ok(())
    }

    async fn validate_google(&self) -> Result<()> {
        Err(Error::from(anyhow!("google not validated")))
    }
}
