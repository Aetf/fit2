use futures::future::poll_fn;
use lambda_http::{
    request::{ApiGatewayRequestContext, ApiGatewayV2RequestContext, Http, RequestContext},
    Body as LambdaBody, Context, Request as LambdaRequest, RequestExt as _, Response,
};

use hyper::service::Service as _;
use routerify::RequestServiceBuilder;
use simple_logger::SimpleLogger;
use std::net::{Ipv4Addr, SocketAddr};

mod adaptor;
mod ext;
mod core;
pub mod error;
mod route;

use adaptor::prelude::*;
use error::*;

pub use route::router;
use crate::ext::Query;

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
                identity.source_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED),
                8080,
            ))
        }
        RequestContext::ApiGatewayV2(ApiGatewayV2RequestContext {
            http: Http { source_ip, .. },
            ..
        }) => {
            log::info!("Got ApiGatewayV2 event");
            SocketAddr::from((source_ip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED), 8080))
        }
        _ => SocketAddr::from(([0, 0, 0, 0], 8080)),
    }
}

type LambdaHttpError = Box<dyn std::error::Error + Send + Sync + 'static>;
pub async fn lambda_http_handler(
    req: LambdaRequest,
    ctx: Context,
) -> std::result::Result<Response<LambdaBody>, LambdaHttpError> {
    log::debug!("{:?}", ctx);
    log::debug!("{:?}", req);
    log::debug!("{:?}", req.request_context());

    let remote_addr = get_remote_addr(&req);
    let mut builder = RequestServiceBuilder::new(route::router())?;
    let mut service = builder.build(remote_addr);
    poll_fn(|ctx| service.poll_ready(ctx)).await?;

    // convert Request<LambdaBody> to Request<hyper::Body>
    let paths = ApiGatewayPath::from_req(&req);
    let queries = Query::from_req(&req);
    let mut req = req.map(|b| b.into_hyper_body());
    req.extensions_mut().insert(paths);
    req.extensions_mut().insert(queries);

    // serve
    let resp: Response<LambdaBody> = service.call(req).await?.map(|b| b.into());

    Ok(resp)
}

impl adaptor::RequestExt for adaptor::Request {
    fn base_path(&self) -> &str {
        let paths: &ApiGatewayPath = self.extensions().get().expect("no apigateway path");
        &paths.base_path
    }
}

struct ApiGatewayPath {
    base_path: String,
}

impl ApiGatewayPath {
    pub fn from_req(req: &LambdaRequest) -> Self {
        let base_path = match req.request_context() {
            RequestContext::ApiGatewayV2(ApiGatewayV2RequestContext {
                stage,
                http,
                ..
                                         }) => {
                if is_default_api_gateway_url(req) {
                    format!("/{}", stage)
                } else {
                    let full_path = req.uri().path();
                    let resource_path_index =
                        full_path.rfind(&http.path).unwrap_or_else(|| {
                            panic!(
                                "Could not find segment '{}' in path '{}'.",
                                &http.path, full_path
                            )
                        });
                    full_path[..resource_path_index].to_owned()
                }
            },
            RequestContext::ApiGateway(ApiGatewayRequestContext {
                stage,
                resource_path,
                ..
            }) => {
                if is_default_api_gateway_url(req) {
                    format!("/{}", stage)
                } else {
                    let resource_path = populate_resource_path(req, resource_path);
                    let full_path = req.uri().path();
                    let resource_path_index =
                        full_path.rfind(&resource_path).unwrap_or_else(|| {
                            panic!(
                                "Could not find segment '{}' in path '{}'.",
                                resource_path, full_path
                            )
                        });
                    full_path[..resource_path_index].to_owned()
                }
            }
            RequestContext::Alb { .. } => String::new(),
        };
        Self{
            base_path,
        }
    }
}

fn is_default_api_gateway_url(req: &LambdaRequest) -> bool {
    req.headers()
        .get(lambda_http::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.ends_with(".amazonaws.com") && h.contains(".execute-api."))
        .unwrap_or(false)
}

fn populate_resource_path(req: &LambdaRequest, resource_path: String) -> String {
    let path_parameters = req.path_parameters();
    resource_path
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') {
                let end = if segment.ends_with("+}") { 2 } else { 1 };
                let param = &segment[1..segment.len() - end];
                path_parameters
                    .get(param)
                    .unwrap_or_else(|| panic!("Could not find path parameter '{}'.", param))
            } else {
                segment
            }
        })
        .collect::<Vec<&str>>()
        .join("/")
}
