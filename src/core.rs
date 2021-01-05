use crate::error::*;
use envy;
use serde::Deserialize;
use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDbClient, ScanInput, DynamoDb, PutItemInput};
use dynomite::FromAttributes;

pub(crate) mod db {
    use dynomite::Item;

    #[derive(Clone, Debug, Default, Item)]
    pub(crate) struct User {
        #[dynomite(partition_key)]
        pub uid: String,
        pub fitbit_access_token: String,
        pub fitbit_refresh_token: String,
        pub google_access_token: String,
        pub google_refresh_token: String,
    }
}
use db::User;

#[derive(Deserialize, Debug)]
struct Config {
    google_client_id: String,
    google_client_secret: String,
    fitbit_client_id: String,
    fitbit_client_secret: String,
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

        Ok(Fit2{
            config,
            db
        })
    }

    pub(crate) async fn get_user(&self) -> Result<Option<User>> {
        let mut input = ScanInput::default();
        input.table_name = self.config.users_table_name.clone();
        input.limit = Some(1);
        let output = self.db.scan(input).await.context("failed to get user")?;
        let user = output.items
            .and_then(|mut items: Vec<_>| items.pop())
            .map(User::from_attrs)
            .transpose()
            .context("invalid user item, corrupted database")?;
        Ok(user)
    }

    pub(crate) async fn put_user(&self, user: &User) -> Result<()> {
        let mut input = PutItemInput::default();
        input.table_name = self.config.users_table_name.clone();
        input.item = user.clone().into();
        self.db.put_item(input).await.context("failed to put_user")?;
        Ok(())
    }
}

impl User {
    pub fn new(uid: impl Into<String>) -> User {
        User {
            uid: uid.into(),
            .. Default::default()
        }
    }
    async fn validate_fitbit(&self) -> Result<()> {
        todo!()
    }

    async fn validate_google(&self) -> Result<()> {
        todo!()
    }
}
