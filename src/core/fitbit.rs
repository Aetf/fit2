use dynomite::{attr_map, FromAttributes, Item};
use oauth2::reqwest::async_http_client;
use oauth2::{AsyncCodeTokenRequest, AsyncRefreshTokenRequest, TokenResponse};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RefreshToken, Scope,
};
use rusoto_dynamodb::{DynamoDb, UpdateItemInput};
use url::Url;

use crate::core::{db::User, Fit2};
use crate::error::*;

enum FitbitState {
    NoAuth,
    AuthNoSub,
    Ok,
}

impl Fit2 {
    pub(crate) async fn fitbit_oauth_start(&self) -> Result<Url> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        // Generate the full authorization URL.
        let (auth_url, csrf_token) = self
            .fitbit_oauth
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            // Set the desired scopes.
            .add_scope(Scope::new("weight".to_string()))
            .url();

        let mut user = self.ensure_user().await?;
        user.fitbit_oauth_csrf = Some(csrf_token.secret().clone());
        user.fitbit_oauth_pkce = Some(pkce_verifier.secret().clone());
        user.set_oauth_state(self).await?;

        Ok(auth_url)
    }

    pub(crate) async fn fitbit_oauth_exchange_token(
        &self,
        csrf: impl AsRef<str>,
        code: impl Into<String>,
    ) -> Result<()> {
        let csrf = csrf.as_ref();
        let code = code.into();

        // check csrf
        let mut user = self.ensure_user().await?;
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

        let token = self
            .fitbit_oauth
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
        user.set_oauth_token(token, refresh, self).await?;
        Ok(())
    }

    // ensure fitbit is fully setup by
    // * refreshing token
    // * setting up subscription
    pub(crate) async fn fitbit_ensure_setup(&self) -> Result<()> {
        let mut user = self.ensure_user().await?;
        loop {
            match user.validate_fitbit().await? {
                FitbitState::NoAuth => {
                    // do auth refresh
                    user.refresh_oauth_token(self).await?;
                }
                FitbitState::AuthNoSub => {
                    // do sub
                    user.setup_subscription().await?;
                }
                FitbitState::Ok => {
                    // ok
                    return Ok(());
                }
            }
        }
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
    // verify that fitbit oauth access token is working
    // and subscription is setup
    async fn validate_fitbit(&self) -> Result<FitbitState> {
        let resp = match reqwest::Client::new()
            .get("https://api.fitbit.com/1/user/-/body/apiSubscriptions.json")
            .bearer_auth(&self.fitbit_access_token)
            .send()
            .await
            .context("fitbit validate get subscriptions list")?
        {
            resp if resp.status() == http::StatusCode::UNAUTHORIZED
                || resp.status() == http::StatusCode::FORBIDDEN =>
            {
                return Ok(FitbitState::NoAuth);
            }
            resp if !resp.status().is_success() => resp
                .error_for_status()
                .context("fitbit validate subscription")?,
            resp => resp,
        };

        // find subscription
        let body: serde_json::Value = resp
            .json()
            .await
            .context("fitbit validate get subscriptions list to json")?;

        let sub = body["apiSubscriptions"].as_array().and_then(|subs| {
            subs.iter()
                .find(|sub| sub["subscriptionId"].as_str() == Some(&self.uid))
        });

        match sub {
            Some(_) => Ok(FitbitState::Ok),
            None => Ok(FitbitState::AuthNoSub),
        }
    }

    async fn set_oauth_state(&mut self, fit2: &Fit2) -> Result<()> {
        let input = UpdateItemInput {
            key: self.key(),
            return_values: Some("ALL_NEW".to_owned()),
            table_name: fit2.config.users_table_name.clone(),
            update_expression: Some(
                "SET fitbit_oauth_csrf = :csrf, fitbit_oauth_pkce = :pkce".to_owned(),
            ),
            expression_attribute_values: Some(attr_map! {
                ":csrf" => self.fitbit_oauth_csrf.take().unwrap_or_default(),
                ":pkce" => self.fitbit_oauth_pkce.take().unwrap_or_default(),
            }),
            ..Default::default()
        };
        let output = fit2
            .db
            .update_item(input)
            .await
            .context("update fitbit oauth state")?;
        *self = User::from_attrs(output.attributes.unwrap_or_default())
            .context("update fitbit oauth state")?;
        Ok(())
    }

    async fn set_oauth_token(&mut self, token: String, refresh: String, fit2: &Fit2) -> Result<()> {
        let input = UpdateItemInput {
            key: self.key(),
            return_values: Some("ALL_NEW".to_owned()),
            table_name: fit2.config.users_table_name.clone(),
            update_expression: Some("SET fitbit_access_token = :token, fitbit_refresh_token = :refresh REMOVE fitbit_oauth_csrf, fitbit_oauth_pkce".to_owned()),
            expression_attribute_values: Some(attr_map!{
                ":token" => token,
                ":refresh" => refresh,
            }),
            .. Default::default()
        };
        let output = fit2
            .db
            .update_item(input)
            .await
            .context("update fitbit oauth token")?;
        *self = User::from_attrs(output.attributes.unwrap_or_default())
            .context("update fitbit oauth token")?;
        Ok(())
    }

    async fn refresh_oauth_token(&mut self, fit2: &Fit2) -> Result<()> {
        let token = fit2
            .fitbit_oauth
            .exchange_refresh_token(&RefreshToken::new(self.fitbit_refresh_token.clone()))
            .request_async(async_http_client)
            .await
            .map_err(|e| anyhow!(format!("{:?}", e)))?;
        let refresh = token
            .refresh_token()
            .ok_or_else(|| anyhow!("Missing Fitbit refresh token"))?
            .secret()
            .clone();
        let token = token.access_token().secret().clone();
        self.set_oauth_token(token, refresh, fit2).await?;
        Ok(())
    }

    async fn setup_subscription(&self) -> Result<()> {
        let client = reqwest::Client::new();
        client
            .delete(&format!(
                "https://api.fitbit.com/1/user/-/body/apiSubscriptions/{}.json",
                &self.uid
            ))
            .bearer_auth(&self.fitbit_access_token)
            .send()
            .await
            .context("fitbit delete subscribe")?;
        client
            .post(&format!(
                "https://api.fitbit.com/1/user/-/body/apiSubscriptions/{}.json",
                &self.uid
            ))
            .bearer_auth(&self.fitbit_access_token)
            .send()
            .await
            .context("fitbit subscribe")?
            .error_for_status()
            .context("fitbit subscribe")?;
        Ok(())
    }
}
