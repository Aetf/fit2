use hyper::body::HttpBody;
use url::form_urlencoded;
use routerify::Middleware;
use lambda_http::{Request as LambdaRequest, RequestExt as _, StrMap};

use crate::adaptor::Request;

pub mod prelude {
    pub use super::RequestQueryExt as _;
}

pub trait RequestQueryExt {
    fn query<P: AsRef<str>>(&self, query_name: P) -> Option<&str>;
}

impl RequestQueryExt for Request {
    fn query<P: AsRef<str>>(&self, query_name: P) -> Option<&str> {
        self.extensions()
            .get::<Query>()
            .and_then(|Query(map)| map.get(query_name.as_ref()))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Query(StrMap);

impl Query {
    pub fn from_req(req: &LambdaRequest) -> Query {
        Query(req.query_string_parameters())
    }
}
