use futures::future::poll_fn;
use lambda_http::{
    request::{ApiGatewayRequestContext, ApiGatewayV2RequestContext, Http, RequestContext},
    Body as LambdaBody, Request as LambdaRequest, Response,
    RequestExt as _,
    Context,
};

use hyper::service::Service as _;
use routerify::RequestServiceBuilder;
use simple_logger::SimpleLogger;
use std::net::{SocketAddr, Ipv4Addr};

mod adaptor;
pub mod error;
mod route;
mod core;

use adaptor::prelude::*;
use error::*;

pub use route::router;

pub async fn init() -> Result<()> {
    // one time init
    SimpleLogger::from_env()
        .with_level(log::LevelFilter::Off)
        .with_module_level("fit2", log::LevelFilter::Debug)
        .with_module_level("local", log::LevelFilter::Info)
        .init()?;
    Ok(())
}

fn get_remote_addr(req: &LambdaRequest) -> SocketAddr {
    match req.request_context() {
        RequestContext::ApiGateway(ApiGatewayRequestContext { identity, .. }) => {
            log::info!("Got ApiGateway event");
            SocketAddr::from((
                identity
                    .source_ip
                    .parse()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
                8080,
            ))
        },
        RequestContext::ApiGatewayV2(ApiGatewayV2RequestContext {
                                         http: Http { source_ip, .. },
                                         ..
                                     }) => {
            log::info!("Got ApiGatewayV2 event");
            SocketAddr::from((
                source_ip
                    .parse()
                    .unwrap_or(Ipv4Addr::UNSPECIFIED),
                8080,
            ))
        },
        _ => SocketAddr::from(([0, 0, 0, 0], 8080)),
    }
}

type LambdaHttpError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub async fn lambda_http_handler(req: LambdaRequest, _ctx: Context) -> std::result::Result<Response<LambdaBody>, LambdaHttpError> {
    let remote_addr = get_remote_addr(&req);
    let mut builder = RequestServiceBuilder::new(route::router())?;
    let mut service = builder.build(remote_addr);
    poll_fn(|ctx| service.poll_ready(ctx)).await?;

    // convert Request<LambdaBody> to Request<hyper::Body>
    let req = req.map(|b| b.into_hyper_body());

    // serve
    let resp: Response<LambdaBody> = service.call(req).await?.map(|b| b.into());

    Ok(resp)
}
