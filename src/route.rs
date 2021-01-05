// Import the routerify prelude traits.
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router};

use crate::error::*;
use crate::adaptor::{http, prelude::*, Body, Request, Response};
use crate::core::{db::User, Fit2};

// Define an app state to share it across the route handlers and middlewares.
struct State(u64);

// A handler for "/" page.
async fn home_handler(req: Request) -> Result<Response> {
    // Access the app state.
    let state = req.data::<State>().unwrap();
    log::info!("State value: {}", state.0);

    Ok("Home page".into_resp())
}

// A handler for "/users/:userId" page.
async fn user_handler(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let user_id = req.param("userId").ok_or_else(|| anyhow!("expected userId"))?;
    match client.get_user().await? {
        Some(user) => Ok(format!("Hello {:?}", &user).into_resp()),
        None => Ok(http::Response::builder().status(http::StatusCode::NOT_FOUND).body(Body::empty())?)
    }
}

async fn create_user(req: Request) -> Result<Response> {
    let client = Fit2::from_env()?;
    let user_id = req.param("userId").ok_or_else(|| anyhow!("expected userId"))?;
    let user = User::new(user_id);
    client.put_user(&user).await?;

    Ok(http::Response::builder()
        .status(http::StatusCode::CREATED)
        .body(Body::empty())?
    )
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
        .middleware(Middleware::post(logger_post))
        .get("/", home_handler)
        .get("/users/:userId", user_handler)
        .post("/users/:userId", create_user)
        .any(not_found)
        .options("/*", global_options)
        .err_handler_with_info(error_handler)
        .build()
        .unwrap()
}
