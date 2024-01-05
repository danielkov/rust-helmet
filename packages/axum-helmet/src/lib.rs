//! Helmet middleware for axum.
//!
//! # Example
//!
//! ```no_run
//! use axum::{routing::get, Router};
//! use axum_helmet::{Helmet, HelmetLayer};
//! use helmet_core::Helmet as HelmetCore;
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new()
//!         .route("/", get(|| async { "Hello, world!" }))
//!         .layer(HelmetLayer::new(
//!             Helmet::new()
//!                 .add(helmet_core::XContentTypeOptions::nosniff())
//!                 .add(helmet_core::XFrameOptions::same_origin())
//!                 .add(helmet_core::XXSSProtection::on().mode_block()),
//!         ));
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```
use std::{
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
};

use http::{header::HeaderName, HeaderMap, HeaderValue, Request, Response};
use pin_project_lite::pin_project;
use tower_service::Service;

use helmet_core::Helmet as HelmetCore;

// re-export helmet_core::* for convenience
pub use helmet_core::*;

/// Create a [`tower::layer::Layer`] that adds helmet headers to responses.
/// See [`helmet_core::Helmet`] for more details.
///
/// # Example
///
/// ```no_run
/// use axum::{routing::get, Router};
/// use axum_helmet::{Helmet, HelmetLayer};
///
/// #[tokio::main]
/// async fn main() {
///     let app = Router::new()
///         .route("/", get(|| async { "Hello, world!" }))
///         .layer(HelmetLayer::new(
///             Helmet::new()
///                 .add(helmet_core::XContentTypeOptions::nosniff())
///                 .add(helmet_core::XFrameOptions::same_origin())
///                 .add(helmet_core::XXSSProtection::on().mode_block()),
///         ));
///
///     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
///     axum::serve(listener, app).await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct HelmetLayer {
    headers: HeaderMap,
}

impl HelmetLayer {
    pub fn new(core: HelmetCore) -> Self {
        let headers = core
            .headers
            .iter()
            .map(|header| {
                (
                    HeaderName::try_from(header.name()).expect("invalid header name"),
                    HeaderValue::try_from(header.value()).expect("invalid header value"),
                )
            })
            .collect();
        Self { headers }
    }
}

impl<S> tower::layer::Layer<S> for HelmetLayer {
    type Service = HelmetInner<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let header_map = self.headers.clone();

        HelmetInner { header_map, inner }
    }
}

#[derive(Clone)]
pub struct HelmetInner<S> {
    header_map: HeaderMap,
    inner: S,
}

impl<S> HelmetInner<S> {
    pub fn new(inner: S) -> Self {
        let header_map = HeaderMap::new();

        Self { header_map, inner }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HelmetInner<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        ResponseFuture {
            future: self.inner.call(req),
            headers: self.header_map.clone(),
        }
    }
}

pin_project! {
    /// Response future for [`SetResponseHeader`].
    #[derive(Debug)]
    pub struct ResponseFuture<F> {
        #[pin]
        future: F,
        headers: HeaderMap,
    }
}

impl<F, ResBody, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<ResBody>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut res = ready!(this.future.poll(cx)?);

        res.headers_mut()
            .extend(this.headers.iter().map(|(k, v)| (k.clone(), v.clone())));

        Poll::Ready(Ok(res))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::{routing::get, Router};
    use axum_test::TestServer;
    use http::{header, HeaderValue};

    #[tokio::test]
    async fn test_helmet() {
        let test_app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(HelmetLayer::new(
                Helmet::new()
                    .add(helmet_core::XContentTypeOptions::nosniff())
                    .add(helmet_core::XFrameOptions::same_origin())
                    .add(helmet_core::XXSSProtection::on().mode_block()),
            ));

        let server = TestServer::new(test_app).expect("failed to create test server");

        let res = server.get("/").await;

        assert_eq!(res.status_code(), 200);

        assert_eq!(
            res.headers().get(header::X_CONTENT_TYPE_OPTIONS),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            res.headers().get(header::X_FRAME_OPTIONS),
            Some(&HeaderValue::from_static("SAMEORIGIN"))
        );
        assert_eq!(
            res.headers().get(header::X_XSS_PROTECTION),
            Some(&HeaderValue::from_static("1; mode=block"))
        );
    }
}
