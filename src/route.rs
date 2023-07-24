// Import the routerify prelude traits.
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router};
use hyper::body::to_bytes;
use futures::lock::Mutex;

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
    let url = match client.fitbit_ensure_setup().await {
        Ok(_) => format!("{}/setup", req.base_path()),
        Err(Error::AuthRedirect(redirect)) => redirect.url.to_string(),
        Err(e) => return Err(e),
    };
    // redirect to fitbit authorize page
    Ok(http::Response::builder()
        .status(http::StatusCode::SEE_OTHER)
        .header(http::header::LOCATION, url)
        .body(Body::empty())?)
}

async fn connect_google(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let url = match client.google_ensure_setup().await {
        Ok(_) => format!("{}/setup", req.base_path()),
        Err(Error::AuthRedirect(redirect)) => redirect.url.to_string(),
        Err(e) => return Err(e),
    };
    // redirect to google authorize page
    Ok(http::Response::builder()
        .status(http::StatusCode::SEE_OTHER)
        .header(http::header::LOCATION, url)
        .body(Body::empty())?)
}

async fn oauth_callback_fitbit(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let user = client.ensure_user().await?;

    let csrf = req
        .query("state");
    let code = req.query("code");
    if let(Some(csrf), Some(code)) = (csrf, code) {
        let mut auth = user.fitbit_auth().lock().await;
        auth.exchange_token(csrf, code).await?;
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

async fn fitbit_sub_notify(req: Request) -> Result<Response> {
    let fit2 = Fit2::from_env()?;

    let sig = req.headers().get("x-fitbit-signature").map(|v| v.as_bytes().to_owned()).unwrap_or_default();
    let body = to_bytes(req.into_body()).await.context("read fitbit notification")?;

    let status = match fit2.fitbit_verify_body(sig, &body).await {
        Err(_) => http::StatusCode::NOT_FOUND,
        Ok(_) => {
            fit2.fitbit_process_notification(body).await?;
            http::StatusCode::NO_CONTENT
        }
    };
    Ok(http::Response::builder()
        .status(status)
        .body(Body::empty())?)
}

struct Data(Mutex<Option<(Fit2, crate::core::User)>>);

async fn client_user(req: Request) -> Result<Request> {
    let data = req.data::<Data>().unwrap().0.lock().await;
    let fit2 = Fit2::from_env()?;
}

async fn client_user_post()

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
        .data(Data(None))
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
