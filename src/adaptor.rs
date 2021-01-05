use futures::task::{Context, Poll};
use hyper::{body::Bytes, http::HeaderValue, HeaderMap};
pub use lambda_http::http;
use lambda_http::Body as LambdaBody;
use std::convert::Infallible;
use tokio::macros::support::Pin;

pub trait IntoHyperBody: Sized {
    fn into_bytes(self) -> Bytes;
    fn into_hyper_body(self) -> hyper::Body {
        self.into_bytes().into()
    }
}

pub trait IntoResp {
    fn into_resp(self) -> Response;
}

pub mod prelude {
    pub use super::IntoHyperBody as _;
    pub use super::IntoResp as _;
    pub use hyper::body::HttpBody as _;
}

impl IntoHyperBody for LambdaBody {
    fn into_bytes(self) -> Bytes {
        match self {
            LambdaBody::Empty => Bytes::new(),
            LambdaBody::Text(s) => s.into(),
            LambdaBody::Binary(b) => b.into(),
        }
    }
}

#[derive(Debug)]
pub struct WrapperBody(Option<LambdaBody>);

impl WrapperBody {
    pub fn empty() -> WrapperBody {
        Self(None)
    }

    pub fn from<T: Into<LambdaBody>>(data: T) -> WrapperBody {
        Self(Some(data.into()))
    }
}

impl Into<LambdaBody> for WrapperBody {
    fn into(self) -> LambdaBody {
        self.0.unwrap_or_default()
    }
}

impl hyper::body::HttpBody for WrapperBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_data(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Data, Self::Error>>> {
        let res = self.0.take().map(|b| Ok(b.into_bytes()));
        Poll::Ready(res)
    }

    fn poll_trailers(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap<HeaderValue>>, Self::Error>> {
        Poll::Ready(Ok(None))
    }
}

impl<T: Into<LambdaBody>> IntoResp for T {
    fn into_resp(self) -> Response {
        Response::new(WrapperBody::from(self))
    }
}

pub type Body = WrapperBody;
pub type Request = http::Request<hyper::Body>;
pub type Response = http::Response<Body>;
