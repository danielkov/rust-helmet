//! Helmet middleware for axum.
//!
//! # Example
//!
//! ```no_run
//! use axum::{routing::get, Router};
//! use axum_helmet::{Helmet, HelmetLayer};
//!
//! #[tokio::main]
//! async fn main() {
//!     let layer: HelmetLayer = Helmet::default().try_into().unwrap();
//!     let app = Router::new()
//!         .route("/", get(|| async { "Hello, world!" }))
//!         .layer(layer);
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

/// Helmet header configuration wrapper.
///
/// Use `Helmet::default()` for a sensible set of default security headers,
/// or `Helmet::new()` to start with no headers and add only the ones you need.
///
/// Convert to [`HelmetLayer`] via `try_into()` to use as axum middleware.
///
/// ```rust
/// use axum_helmet::{Helmet, HelmetLayer};
///
/// let layer: HelmetLayer = Helmet::default().try_into().unwrap();
/// ```
#[derive(Default)]
pub struct Helmet(HelmetCore);

impl Helmet {
    /// Create a new instance of `Helmet` with no headers set.
    pub fn new() -> Self {
        Self(HelmetCore::new())
    }

    /// Add a header.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, header: impl Into<helmet_core::Header>) -> Self {
        Self(self.0.add(header))
    }

    pub fn into_layer(self) -> Result<HelmetLayer, HelmetError> {
        self.try_into()
    }
}

/// Create a [`tower::layer::Layer`] that adds helmet headers to responses.
///
/// # Example
///
/// ```no_run
/// use axum::{routing::get, Router};
/// use axum_helmet::{Helmet, HelmetLayer};
///
/// #[tokio::main]
/// async fn main() {
///     let layer: HelmetLayer = Helmet::new()
///         .add(helmet_core::XContentTypeOptions::nosniff())
///         .add(helmet_core::XFrameOptions::same_origin())
///         .add(helmet_core::XXSSProtection::on().mode_block())
///         .try_into()
///         .unwrap();
///
///     let app = Router::new()
///         .route("/", get(|| async { "Hello, world!" }))
///         .layer(layer);
///
///     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
///     axum::serve(listener, app).await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct HelmetLayer {
    headers: HeaderMap,
}

impl TryFrom<Helmet> for HelmetLayer {
    type Error = HelmetError;

    fn try_from(helmet: Helmet) -> Result<Self, Self::Error> {
        let mut headers = HeaderMap::new();
        for header in helmet.0.headers.iter() {
            let name = HeaderName::try_from(header.0)
                .map_err(|_| HelmetError::InvalidHeaderName(header.0.to_string()))?;
            let value = HeaderValue::try_from(&header.1)
                .map_err(|_| HelmetError::InvalidHeaderValue(header.1.clone()))?;
            headers.insert(name, value);
        }
        Ok(Self { headers })
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
    /// Response future for [`HelmetInner`].
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

        for (name, value) in this.headers.iter() {
            res.headers_mut().insert(name.clone(), value.clone());
        }

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
            .layer(
                Helmet::new()
                    .add(helmet_core::XContentTypeOptions::nosniff())
                    .add(helmet_core::XFrameOptions::same_origin())
                    .add(helmet_core::XXSSProtection::on().mode_block())
                    .into_layer()
                    .unwrap(),
            );

        let server = TestServer::new(test_app);

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
