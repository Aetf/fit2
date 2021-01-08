// Import the routerify prelude traits.
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router};

use crate::adaptor::{http, prelude::*, Body, Request, Response};
use crate::core::Fit2;
use crate::error::*;
use crate::ext::prelude::*;

mod templates;
use templates::{SetupPage, Template};

async fn setup_page(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let html = SetupPage {
        valid_fitbit: client.fitbit_ensure_setup().await.is_ok(),
        valid_google: client.google_ensure_setup().await.is_ok(),
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
    let url = if let Ok(_) = client.fitbit_ensure_setup().await {
        format!("{}/setup", req.base_path())
    } else {
        client.fitbit_oauth_start().await?.to_string()
    };
    // redirect to fitbit authorize page
    Ok(http::Response::builder()
        .status(http::StatusCode::SEE_OTHER)
        .header(http::header::LOCATION, url)
        .body(Body::empty())?)
}

async fn connect_google(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let url = if let Ok(_) = client.google_ensure_setup().await {
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
        .query("state");
    let code = req.query("code");
    if let(Some(csrf), Some(code)) = (csrf, code) {
        client.fitbit_oauth_exchange_token(csrf, code).await?;
    }
    client.fitbit_ensure_setup().await?;

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
    Ok(http::Response::builder().status(code).body(Body::empty())?)
}

async fn fitbit_sub_notify(_req: Request) -> Result<Response> {
    log::warn!("Stub sub notify");
    Ok(http::Response::builder()
        .status(http::StatusCode::NO_CONTENT)
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
