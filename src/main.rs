use futures::future::poll_fn;
use lambda_http::RequestExt as _;
use lambda_http::{handler, lambda};
use lambda_http::{
    request::{ApiGatewayRequestContext, ApiGatewayV2RequestContext, Http, RequestContext},
    Body as LambdaBody, Request as LambdaRequest, Response,
};

use hyper::service::Service as _;
use routerify::RequestServiceBuilder;
use simple_logger::SimpleLogger;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

mod adaptor;
mod error;
mod route;

use adaptor::prelude::*;
use error::Result;

fn get_remote_addr(req: &LambdaRequest) -> SocketAddr {
    match req.request_context() {
        RequestContext::ApiGateway(ApiGatewayRequestContext { identity, .. }) => SocketAddr::new(
            identity
                .source_ip
                .parse()
                .unwrap_or_else(|_| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            8080,
        ),
        RequestContext::ApiGatewayV2(ApiGatewayV2RequestContext {
            http: Http { source_ip, .. },
            ..
        }) => SocketAddr::new(
            source_ip
                .parse()
                .unwrap_or_else(|_| IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            8080,
        ),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // one time init
    SimpleLogger::new().init()?;

    // run handlers
    lambda::run(handler(|req: LambdaRequest, _ctx| async {
        let remote_addr = get_remote_addr(&req);
        let mut builder = RequestServiceBuilder::new(route::router())?;
        let mut service = builder.build(remote_addr);
        poll_fn(|ctx| service.poll_ready(ctx)).await?;

        // convert Request<LambdaBody> to Request<hyper::Body>
        let req = req.map(|b| b.into_hyper_body());

        // serve
        let resp: Response<LambdaBody> = service.call(req).await?.map(|b| b.into());

        Ok(resp)
    }))
    .await?;
    Ok(())
}
