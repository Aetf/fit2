use fit2::{error::*, init, lambda_http_handler};
use lambda_http::{handler, lambda};

#[tokio::main]
async fn main() -> Result<()> {
    init().await?;

    lambda::run(handler(lambda_http_handler)).await?;

    Ok(())
}
