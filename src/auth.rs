use oauth2::{CsrfToken, PkceCodeVerifier, PkceCodeChallenge, AuthorizationCode, AsyncCodeTokenRequest, TokenResponse, AsyncRefreshTokenRequest};
use oauth2::Scope;
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::reqwest::async_http_client;
use url::Url;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::mem;
use futures::lock::Mutex;

use crate::error::*;
use std::sync::Arc;

pub use oauth2::AccessToken;

#[derive(Debug, Clone)]
pub struct OAuthRedirect {
    pub url: Url,
}

impl OAuthRedirect {
    pub fn into_err<T>(self) -> Result<T> {
        Err(Error::oauth_redirect(self))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum OAuthState {
    None,
    WaitCode{
        url: Url,
        csrf: CsrfToken,
        pkce_verifier: PkceCodeVerifier,
    },
    Authorized(BasicTokenResponse),
}

impl Default for OAuthState {
    fn default() -> Self {
        Self::None
    }
}

impl Clone for OAuthState {
    fn clone(&self) -> Self {
        match self {
            Self::None => Self::None,
            Self::WaitCode { url, csrf, pkce_verifier } => Self::WaitCode {
                url: url.clone(),
                csrf: csrf.clone(),
                pkce_verifier: PkceCodeVerifier::new(pkce_verifier.secret().clone())
            },
            Self::Authorized(token) => Self::Authorized(token.clone()),
        }
    }
}

pub struct AuthorizationCodeFlow {
    state: OAuthState,
    oauth: BasicClient,
}

impl AuthorizationCodeFlow {
    pub fn new(oauth: BasicClient) -> AuthorizationCodeFlow {
        Self::from_state(oauth, OAuthState::None)
    }

    pub fn from_state(oauth: BasicClient, state: OAuthState) -> AuthorizationCodeFlow {
        Self {
            oauth,
            state,
        }
    }

    pub fn take_state(&mut self) -> OAuthState {
        mem::replace(&mut self.state, OAuthState::None)
    }

    pub fn state(&self) -> &OAuthState {
        &self.state
    }

    pub async fn gen_redirect(&mut self, scopes: impl IntoIterator<Item=Scope>) -> Result<OAuthRedirect> {
        if let OAuthState::WaitCode {url, .. } = &self.state {
            return Ok(OAuthRedirect{ url: url.clone() });
        }

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        // Generate the full authorization URL.
        let mut auth_req = self.oauth
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);
        for scope in scopes {
            auth_req = auth_req.add_scope(scope);
        }
        let (url, csrf) = auth_req.url();

        self.state = OAuthState::WaitCode{
            url: url.clone(),
            csrf,
            pkce_verifier,
        };

        let redirect = OAuthRedirect { url };
        log::info!("Starting oauth: {}", &redirect.url);

        Ok(redirect)
    }

    pub async fn exchange_token(&mut self, csrf: impl AsRef<str>, code: impl Into<String>) -> Result<&AccessToken> {
        let state = mem::replace(&mut self.state, OAuthState::None);
        let token = if let OAuthState::WaitCode{ csrf : csrf_saved, pkce_verifier, .. } = state {
            let csrf = csrf.as_ref();
            let code = code.into();

            log::info!("Exchanging oauth token");

            // check csrf
            if csrf_saved.secret() != csrf {
                return Err(anyhow!("csrf mismatch: got {} expected {:?}", csrf, csrf_saved).into());
            }

            self
                .oauth
                .exchange_code(AuthorizationCode::new(code))
                .set_pkce_verifier(pkce_verifier)
                .request_async(async_http_client)
                .await
                .map_err(|e| anyhow!(format!("{:?}", e)))?
        } else {
            return Err(anyhow!("Invalid state").into());
        };

        self.state = OAuthState::Authorized(token);

        if let OAuthState::Authorized(token) = &self.state {
            Ok(token.access_token())
        } else {
            unreachable!("Unreachable!")
        }
    }

    pub async fn refresh_token(&mut self, scopes: impl IntoIterator<Item=Scope>) -> Result<()>
    {
        log::info!("Refreshing oauth token");
        match self.take_state() {
            OAuthState::Authorized(token) if token.refresh_token().is_some() => {
                let new_token = self.oauth
                    .exchange_refresh_token(token.refresh_token().unwrap())
                    .request_async(async_http_client)
                    .await
                    .map_err(|e| anyhow!(format!("{:?}", e)))?;
                self.state = OAuthState::Authorized(new_token);
                Ok(())
            },
            OAuthState::WaitCode { url, csrf, pkce_verifier } => {
                self.state = OAuthState::WaitCode { url: url.clone(), csrf, pkce_verifier };
                OAuthRedirect { url }.into_err()
            },
            _ => {
                self.gen_redirect(scopes).await?.into_err()
            }
        }
    }
}

#[async_trait]
pub trait Authenticator {
    async fn token<'a, 'b, SIntoIter, SIter, S>(&'a self, scopes: SIntoIter) -> Result<AccessToken>
        where
            SIntoIter: 'b + IntoIterator<IntoIter=SIter> + Send,
            SIter: Iterator<Item=S> + Send,
            S: ToString
    ;
    async fn refresh<'a, 'b, SIntoIter, SIter, S>(&'a self, scopes: SIntoIter) -> Result<()>
        where
            SIntoIter: 'b + IntoIterator<IntoIter=SIter> + Send,
            SIter: Iterator<Item=S> + Send,
            S: ToString
    ;
}

#[async_trait]
impl Authenticator for Arc<Mutex<AuthorizationCodeFlow>> {
    async fn token<'a, 'b, SIntoIter, SIter, S>(&'a self, scopes: SIntoIter) -> Result<AccessToken>
    where
        SIntoIter: 'b + IntoIterator<IntoIter=SIter> + Send,
        SIter: Iterator<Item=S> + Send,
        S: ToString
    {
        let mut this = self.lock().await;
        match &this.state {
            OAuthState::None => {
                let scopes = scopes.into_iter().map(|s| Scope::new(s.to_string()));
                this.gen_redirect(scopes).await?.into_err()
            },
            OAuthState::WaitCode{ url, .. } => OAuthRedirect {
                url: url.clone(),
            }.into_err(),
            OAuthState::Authorized(token) => Ok(token.access_token().clone())
        }
    }

    async fn refresh<'a, 'b, SIntoIter, SIter, S>(&'a self, scopes: SIntoIter) -> Result<()>
        where
            SIntoIter: 'b + IntoIterator<IntoIter=SIter> + Send,
            SIter: Iterator<Item=S> + Send,
            S: ToString
    {
        let mut this = self.lock().await;
        let scopes = scopes.into_iter().map(|s| Scope::new(s.to_string()));
        this.refresh_token(scopes).await
    }
}
