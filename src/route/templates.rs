pub use askama::Template;

use crate::core::db::User;

#[derive(Template, Debug)]
#[template(path = "setup.jinja.html")]
pub struct SetupPage {
    pub valid_google: bool,
    pub valid_fitbit: bool,
    pub base_path: String,
}
