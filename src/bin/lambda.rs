use fit2::{init, lambda_http_handler, error::*};
use lambda_http::{lambda, handler};

#[tokio::main]
async fn main() -> Result<()> {
    init().await?;

    lambda::run(handler(lambda_http_handler)).await?;

    Ok(())
}
