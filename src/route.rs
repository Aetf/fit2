// Import the routerify prelude traits.
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router};

use crate::error::{Error, Result};

use crate::adaptor::{http, prelude::*, Body, Request, Response};

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
    let user_id = req.param("userId").unwrap();
    Ok(format!("Hello {}", user_id).into_resp())
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

// Define an error handler function which will accept the `routerify::Error`
// and the request information and generates an appropriate response.
async fn error_handler(err: routerify::Error, _: RequestInfo) -> Response {
    log::error!("{}", err);
    http::Response::builder()
        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(format!("Something went wrong: {}", err)))
        .unwrap()
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
        .get("/", home_handler)
        .get("/users/:userId", user_handler)
        .err_handler_with_info(error_handler)
        .build()
        .unwrap()
}
