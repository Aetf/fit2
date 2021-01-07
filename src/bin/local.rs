use fit2::{error::*, init, router};
use hyper::Server;
use routerify::RouterService;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    init().await?;

    // Create a Service from the router above to handle incoming requests.
    let service = RouterService::new(router())?;

    // The address on which the server will be listening.
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    // Create a server by passing the created service to `.serve` method.
    let server = Server::bind(&addr).serve(service);

    log::info!("App is running on: {}", addr);
    server.await?;
    Ok(())
}
