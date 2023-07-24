use chrono::{Utc, DateTime};
use http::status::StatusCode;

use crate::core::{User, Fit2};
use crate::error::*;
use crate::auth::Authenticator;

mod gen {
    pub(super) mod fitness_v1_types;
}
use gen::fitness_v1_types:: {self as fitness, UsersDataSourcesGetParams, FitnessScopes};


impl Fit2 {
    pub(crate) async fn google_ensure_setup(&self) -> Result<()> {
        let user = self.ensure_user().await?;
        loop {
            let s = user.validate_google().await?;
            log::debug!("Google state {:?}", &s);
            match s {
                GoogleState::NeedAuth => {
                    user.google_auth().refresh(&[FitnessScopes::FitnessBodyRead, FitnessScopes::FitnessBodyWrite]).await?;
                }
                GoogleState::NoSetup => {
                    todo!()
                },
                GoogleState::Ok => return Ok(()),
            }
        }
    }

    pub(crate) async fn google_ensure_last_sync_dt(&self) -> Result<DateTime<Utc>> {
        todo!()
    }
}

#[derive(Debug)]
enum GoogleState {
    NeedAuth,
    NoSetup,
    Ok,
}

impl User {
    // verify that google oauth access token is working
    // and data source is setup
    async fn validate_google(&self) -> Result<GoogleState> {
        log::debug!("Validating google");
        let mut service = fitness::UsersDataSourcesService::new(
            fitness::default_https_client(),
            self.google_auth.clone(),
        );
        let data_source_id = match self.google_data_source_id() {
            Some(id) => id.clone(),
            None => return Ok(GoogleState::NoSetup),
        };
        let params = UsersDataSourcesGetParams {
            fitness_params: None,
            user_id: "me".to_string(),
            data_source_id,
        };
        match service.get(&params).await {
            Ok(_) => Ok(GoogleState::Ok),
            Err(err) => {
                match err.downcast_ref() {
                    Some(fitness::ApiError::HTTPResponseError(StatusCode::NOT_FOUND, ..)) => Ok(GoogleState::NoSetup),
                    Some(fitness::ApiError::HTTPResponseError(StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED, ..)) => Ok(GoogleState::NeedAuth),
                    _ => Err(err.into()),
                }
            }
        }
    }
}
