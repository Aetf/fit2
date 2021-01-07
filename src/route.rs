// Import the routerify prelude traits.
use oauth2::url::Url;
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router};

use crate::adaptor::{http, prelude::*, Body, Request, Response};
use crate::core::{db::User, Fit2};
use crate::error::*;
use crate::ext::prelude::*;

mod templates;
use templates::{SetupPage, Template};

// Define an app state to share it across the route handlers and middlewares.
struct State(u64);

// A handler for "/" page.
async fn home_handler(req: Request) -> Result<Response> {
    // Access the app state.
    let state = req.data::<State>().unwrap();
    log::info!("State value: {}", state.0);

    Ok("Home page".into_resp())
}

async fn setup_page(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let html = SetupPage {
        valid_fitbit: client.ensure_fitbit_token().await.is_ok(),
        valid_google: client.ensure_google_token().await.is_ok(),
        base_path: req.base_path().to_owned(),
    }
    .render()
    .context("render setup page")?;
    Ok(http::Response::builder()
        .status(http::StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Body::from(html))?)
}

async fn connect_fitbit(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let url = if let Ok(_) = client.ensure_fitbit_token().await {
        format!("{}/setup", req.base_path())
    } else {
        client.fitbit_oauth_redirect().await?.to_string()
    };
    // redirect to fitbit authorize page
    Ok(http::Response::builder()
        .status(http::StatusCode::SEE_OTHER)
        .header(http::header::LOCATION, url)
        .body(Body::empty())?)
}

async fn connect_google(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let url = if let Ok(_) = client.ensure_google_token().await {
        format!("{}/setup", req.base_path())
    } else {
        client.google_oauth_redirect().await?.to_string()
    };
    // redirect to fitbit authorize page
    Ok(http::Response::builder()
        .status(http::StatusCode::SEE_OTHER)
        .header(http::header::LOCATION, url)
        .body(Body::empty())?)
}

async fn oauth_callback_fitbit(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let csrf = req
        .query("state")
        .ok_or_else(|| anyhow!("expected state"))?;
    let code = req.query("code").ok_or_else(|| anyhow!("expected code"))?;
    client.fitbit_oauth_token(csrf, code).await?;

    let url = format!("{}/setup", req.base_path());

    Ok(http::Response::builder()
        .status(http::StatusCode::SEE_OTHER)
        .header(http::header::LOCATION, url)
        .body(Body::empty())?)
}

async fn fitbit_sub_verify(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let code = match client.fitbit_sub_verify(req.query("verify")).await {
        Ok(_) => http::StatusCode::NO_CONTENT,
        Err(_) => http::StatusCode::NOT_FOUND,
    };
    Ok(http::Response::builder()
        .status(code)
        .body(Body::empty())?)
}

async fn fitbit_sub_notify(req: Request) -> Result<Response> {
    log::warn!("Stub sub notify");
    Ok(http::Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .body(Body::empty())?)
}

// A handler for "/users/:userId" page.
async fn user_handler(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let user_id = req
        .param("userId")
        .ok_or_else(|| anyhow!("expected userId"))?;
    match client.get_user().await? {
        Some(user) => Ok(format!("Hello {:?}", &user).into_resp()),
        None => Ok(http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(Body::empty())?),
    }
}

async fn create_user(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let user_id = req
        .param("userId")
        .ok_or_else(|| anyhow!("expected userId"))?;
    let user = User::new(user_id);
    client.put_user(&user).await?;

    Ok(http::Response::builder()
        .status(http::StatusCode::CREATED)
        .body(Body::empty())?)
}

// A middleware which logs an http request.
async fn logger(req: Request) -> Result<Request> {
    log::info!(
        "{} {} {}",
        req.remote_addr(),
        req.method(),
        req.uri().path()
    );
    Ok(req)
}

async fn logger_post(resp: Response) -> Result<Response> {
    log::info!("{:?}", &resp);
    Ok(resp)
}

// Define an error handler function which will accept the `routerify::Error`
// and the request information and generates an appropriate response.
async fn error_handler(err: routerify::Error, _: RequestInfo) -> Response {
    let err = anyhow!(err);
    log::error!("{:?}", err);
    http::Response::builder()
        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(format!("Something went wrong: {:?}", err)))
        .unwrap()
}

async fn not_found(_req: Request) -> Result<Response> {
    let resp = http::Response::builder()
        .status(http::StatusCode::NOT_FOUND)
        .body(Body::from("NOT FOUND"))?;
    Ok(resp)
}

async fn global_options(_req: Request) -> Result<Response> {
    let resp = http::Response::builder()
        .status(http::StatusCode::NO_CONTENT)
        .body(Body::empty())?;
    Ok(resp)
}

pub fn router() -> Router<Body, Error> {
    // Create a router and specify the logger middleware and the handlers.
    // Here, "Middleware::pre" means we're adding a pre middleware which will be executed
    // before any route handlers.
    Router::builder()
        // Specify the state data which will be available to every route handlers,
        // error handler and middlewares.
        .data(State(100))
        .middleware(Middleware::pre(logger))
        .get("/setup", setup_page)
        .get("/api/auth/fitbit", connect_fitbit)
        .get("/api/auth/fitbit/callback", oauth_callback_fitbit)
        .get("/api/auth/google", connect_google)
        .get("/api/fitbit/notification", fitbit_sub_verify)
        .post("/api/fitbit/notification", fitbit_sub_notify)
        .any(not_found)
        .options("/*", global_options)
        .err_handler_with_info(error_handler)
        .middleware(Middleware::post(logger_post))
        .build()
        .unwrap()
}
