use dynomite::{attr_map, FromAttributes, Item};
use oauth2::reqwest::async_http_client;
use oauth2::{AsyncCodeTokenRequest, AsyncRefreshTokenRequest, TokenResponse};
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RefreshToken, Scope,
};
use rusoto_dynamodb::{DynamoDb, UpdateItemInput};
use url::Url;
use sha1::Sha1;
use hmac::{Hmac, Mac, NewMac};
use percent_encoding::percent_decode;
use fitbit_web_api as fitbit;
use chrono::{TimeZone, NaiveDate};

use crate::core::{db::User, Fit2};
use crate::error::*;
use std::borrow::Cow;
use chrono::{DateTime, Utc, Date};
use crate::utils::{DateRangeChunksExt as _};
use std::iter::{once, once_with};

#[derive(Debug)]
enum FitbitState {
    NoAuth,
    AuthNoSub,
    Ok,
}

type HmacSha1 = Hmac<Sha1>;

impl Fit2 {
    // verify the body against signature
    pub(crate) async fn fitbit_verify_body(&self, sig: impl AsRef<[u8]>, body: impl AsRef<[u8]>) -> Result<()> {
        let sig = sig.as_ref();
        let body = body.as_ref();

        // decode the signature
        let sig: Cow<[u8]> = percent_decode(sig).into();
        let sig = base64::decode(&sig).context("base64 decode signature")?;
        log::debug!("Signature to verify: {:?}", &sig);

        // compute signature on body
        let key = self.config.fitbit_client_secret.clone() + "&";
        let key = key.as_bytes();
        log::debug!("Using key {:?}", &key);
        let mut mac = HmacSha1::new_varkey(key).expect("HMAC can take any key size");
        mac.update(body);
        // verify
        mac.verify(&sig).context("invalid fitbit signature")?;
        Ok(())
    }

    pub(crate) async fn fitbit_process_notification(&self, body: impl AsRef<[u8]>) -> Result<()> {
        let body: serde_json::Value = serde_json::from_slice(body.as_ref())
            .context("deserialize fitbit notification")?;
        log::debug!("Got fitbit notification {:?}", body);

        // TODO: process fitbit notification
        // self.sync_fitbit_to_google().await?;

        Ok(())
    }

    pub(crate) async fn fitbit_member_since(&self) -> Result<Date<Utc>> {
        let mut user = self.ensure_user().await?;
        if let Some(dt) = user.fitbit_member_since {
            return Ok(dt.date());
        }

        // read profile and get memberSince
        let profile = user.get_profile().await?;
        let member_since = match profile.timezone.from_local_date(&profile.member_since) {
            chrono::LocalResult::Single(date) => date,
            _ => return Err(anyhow!("invalid fitbit profile").into()),
        }
            .with_timezone(&Utc);
        user.set_member_since(member_since, self).await?;

        Ok(user.fitbit_member_since.unwrap().date())
    }

    // handles chunking into month long periods and filtering out points based on time on the date of minTime and maxTime
    pub(crate) async fn fitbit_get_data_points(&self, min_time: DateTime<Utc>, max_time: DateTime<Utc>) -> Result<Vec<fitbit::body::log::weight::WeightLog>> {
        // first get timezone from profile: user.timezone: "America/New_York"
        let user = self.ensure_user().await?;
        let profile = user.get_profile().await?;
        let min_time = min_time.with_timezone(&profile.timezone);
        let max_time = max_time.with_timezone(&profile.timezone);

        let min_date = min_time.naive_local().date();
        let max_date = max_time.naive_local().date();

        let futures = (min_date..=max_date).chunks(31)
            .map(|chunk| {
                user.get_weight_log(chunk.start, chunk.end.pred())
            });
        let result: Vec<_> = futures::future::join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .context("get data points")?
            .into_iter()
            .flatten()
            .collect();

        log::debug!("{:?}", &result);

        Ok(result)
    }

    pub(crate) async fn fitbit_oauth_start(&self) -> Result<Url> {

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        // Generate the full authorization URL.
        let (auth_url, csrf_token) = self
            .fitbit_oauth
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge)
            // Set the desired scopes.
            .add_scope(Scope::new("weight".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();

        let mut user = self.ensure_user().await?;
        user.fitbit_oauth_csrf = Some(csrf_token.secret().clone());
        user.fitbit_oauth_pkce = Some(pkce_verifier.secret().clone());
        user.set_oauth_state(self).await?;

        log::info!("Starting oauth: {}", &auth_url);

        Ok(auth_url)
    }

    pub(crate) async fn fitbit_oauth_exchange_token(
        &self,
        csrf: impl AsRef<str>,
        code: impl Into<String>,
    ) -> Result<()> {
        let csrf = csrf.as_ref();
        let code = code.into();

        log::info!("Exchanging oauth token");

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
            let s = user.validate_fitbit().await?;
            log::debug!("Fitbit state: {:?}", s);
            match s {
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
        log::info!("Verifying subscription endpoint with code: {:?}", &verify);
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
        log::debug!("Validating subscription");
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
        log::debug!("Setting oauth state in DB");
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
        log::info!("Setting oauth token in DB");
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

    async fn set_member_since(&mut self, member_since: Date<Utc>, fit2: &Fit2) -> Result<()> {
        log::debug!("Setting member_since in DB");
        let input = UpdateItemInput {
            key: self.key(),
            return_values: Some("ALL_NEW".to_owned()),
            table_name: fit2.config.users_table_name.clone(),
            update_expression: Some("SET fitbit_member_since = :since".to_owned()),
            expression_attribute_values: Some(attr_map!{
                ":since" => member_since.and_hms(0, 0, 0),
            }),
            .. Default::default()
        };
        let output = fit2
            .db
            .update_item(input)
            .await
            .context("update fitbit member_since")?;
        *self = User::from_attrs(output.attributes.unwrap_or_default())
            .context("update fitbit member_since")?;
        Ok(())
    }

    async fn refresh_oauth_token(&mut self, fit2: &Fit2) -> Result<()> {
        log::info!("Refreshing oauth token");
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
        log::debug!("Removing old subscription");
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
        log::info!("Adding new subscription");
        client
            .post(&format!(
                "https://api.fitbit.com/1/user/-/body/apiSubscriptions/{}.json",
                &self.uid
            ))
            .bearer_auth(&self.fitbit_access_token)
            .form(&[("subscriberId", "1")])
            .send()
            .await
            .context("fitbit subscribe")?
            .error_for_status()
            .context("fitbit subscribe")?;
        Ok(())
    }

    async fn get_profile(&self) -> Result<fitbit::user::profile::User> {
        log::debug!("Getting user profile");
        let client = reqwest::Client::new();
        let profile: fitbit::user::profile::Response = client.get(fitbit::user::profile::url(fitbit::UserId::Current))
            .bearer_auth(&self.fitbit_access_token)
            .send()
            .await
            .context("fitbit get profile")?
            .json()
            .await
            .context("fitbit get profile json")?;

        Ok(profile.user)
    }

    async fn get_weight_log(&self, min: NaiveDate, max: NaiveDate) -> Result<Vec<fitbit::body::log::weight::WeightLog>> {
        log::debug!("Getting weight log");
        let client = reqwest::Client::new();
        let resp: fitbit::body::log::weight::GetResponse = client.get(
            fitbit::body::log::url_from_date_range(
                &fitbit::UserId::Current,
                fitbit::body::log::Resource::Weight,
                min,
                max,
            )
        )
            .bearer_auth(&self.fitbit_access_token)
            .send()
            .await
            .context("fitbit get weight")?
            .json()
            .await
            .context("fitbit get weight json")?;
        Ok(resp.weight)
    }
}
