//! `poem-helmet` is a security middleware for the Poem web framework that sets various HTTP headers to help protect your app.
//!
//! `poem_helmet::Helmet` is a middleware that automatically sets security headers on all responses.
//!
//! It is based on the [Helmet](https://helmetjs.github.io/) library for Node.js and is highly configurable.
//!
//! # Usage
//!
//! ```no_run
//! use poem::{get, handler, listener::TcpListener, EndpointExt, Route, Server};
//! use poem_helmet::Helmet;
//!
//! #[handler]
//! fn index() -> &'static str {
//!     "Hello, world!"
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let app = Route::new()
//!         .at("/", get(index))
//!         .with(Helmet::default().into_middleware()?);
//!
//!     Server::new(TcpListener::bind("0.0.0.0:3000"))
//!         .run(app)
//!         .await?;
//!     Ok(())
//! }
//! ```
//!
//! By default Helmet will set the following headers:
//!
//! ```text
//! Content-Security-Policy: default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests
//! Cross-Origin-Opener-Policy: same-origin
//! Cross-Origin-Resource-Policy: same-origin
//! Origin-Agent-Cluster: ?1
//! Referrer-Policy: no-referrer
//! Strict-Transport-Security: max-age=15552000; includeSubDomains
//! X-Content-Type-Options: nosniff
//! X-DNS-Prefetch-Control: off
//! X-Download-Options: noopen
//! X-Frame-Options: sameorigin
//! X-Permitted-Cross-Domain-Policies: none
//! X-XSS-Protection: 0
//! ```
//!
//! This might be a good starting point for most users, but it is highly recommended to spend some time with the documentation for each header, and adjust them to your needs.
//!
//! # Configuration
//!
//! By default if you construct a new instance of `Helmet` it will not set any headers.
//!
//! It is possible to configure `Helmet` to set only the headers you want, by using the `add` method to add headers.
//!
//! ```no_run
//! use poem::{get, handler, listener::TcpListener, EndpointExt, Route, Server};
//! use poem_helmet::{Helmet, ContentSecurityPolicy, CrossOriginOpenerPolicy, HelmetMiddleware};
//!
//! #[handler]
//! fn index() -> &'static str {
//!     "Hello, world!"
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let helmet: HelmetMiddleware = Helmet::new()
//!         .add(
//!             ContentSecurityPolicy::new()
//!                 .default_src(vec!["'self'"])
//!                 .script_src(vec!["'self'", "https://cdn.example.com"]),
//!         )
//!         .add(CrossOriginOpenerPolicy::same_origin_allow_popups())
//!         .try_into()?;
//!
//!     let app = Route::new()
//!         .at("/", get(index))
//!         .with(helmet);
//!
//!     Server::new(TcpListener::bind("0.0.0.0:3000"))
//!         .run(app)
//!         .await?;
//!     Ok(())
//! }
//! ```
use http::header::{HeaderMap, HeaderName, HeaderValue};
use poem::{Endpoint, IntoResponse, Middleware, Request, Response, Result};

use helmet_core::Helmet as HelmetCore;

// re-export helmet_core::*, except for the `Helmet` struct
pub use helmet_core::*;

/// Helmet header configuration wrapper.
///
/// Use `Helmet::default()` for a sensible set of default security headers,
/// or `Helmet::new()` to start with no headers and add only the ones you need.
///
/// Convert to [`HelmetMiddleware`] via `try_into()` to use as Poem middleware.
///
/// ```rust
/// use poem_helmet::{Helmet, HelmetMiddleware};
///
/// let middleware: HelmetMiddleware = Helmet::default().try_into().unwrap();
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

    /// Convert into [`HelmetMiddleware`].
    ///
    /// Poem's `EndpointExt::with()` takes `T: Middleware<E>`, but Rust's type
    /// inference cannot resolve the target type of `try_into()` through the `?`
    /// operator, so `.with(helmet.try_into()?)` does not compile. This method
    /// lets you write `.with(helmet.into_middleware()?)` instead.
    pub fn into_middleware(self) -> Result<HelmetMiddleware, HelmetError> {
        self.try_into()
    }
}

/// The Poem middleware created by converting a [`Helmet`] configuration.
pub struct HelmetMiddleware {
    headers: HeaderMap,
}

impl TryFrom<Helmet> for HelmetMiddleware {
    type Error = HelmetError;

    fn try_from(helmet: Helmet) -> std::result::Result<Self, Self::Error> {
        let mut headers = HeaderMap::new();
        for header in helmet.0.headers.iter() {
            let name = HeaderName::try_from(header.0)
                .map_err(|_| HelmetError::InvalidHeaderName(header.0.to_string()))?;
            let value = HeaderValue::from_str(&header.1)
                .map_err(|_| HelmetError::InvalidHeaderValue(header.1.clone()))?;
            headers.insert(name, value);
        }
        Ok(Self { headers })
    }
}

impl<E: Endpoint> Middleware<E> for HelmetMiddleware {
    type Output = HelmetEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        HelmetEndpoint {
            ep,
            headers: self.headers.clone(),
        }
    }
}

/// The endpoint wrapper created by [`HelmetMiddleware`].
pub struct HelmetEndpoint<E> {
    ep: E,
    headers: HeaderMap,
}

impl<E: Endpoint> Endpoint for HelmetEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> Result<Self::Output> {
        let mut resp = self.ep.call(req).await?.into_response();
        for (name, value) in self.headers.iter() {
            resp.headers_mut().insert(name.clone(), value.clone());
        }
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poem::{handler, test::TestClient, EndpointExt, Route};

    #[handler]
    fn index() -> &'static str {
        "Hello, world!"
    }

    #[tokio::test]
    async fn test_helmet() {
        let mw: HelmetMiddleware = Helmet::new()
            .add(helmet_core::XContentTypeOptions::nosniff())
            .add(helmet_core::XFrameOptions::same_origin())
            .add(helmet_core::XXSSProtection::on().mode_block())
            .try_into()
            .unwrap();

        let app = Route::new().at("/", index).with(mw);

        let client = TestClient::new(app);
        let resp = client.get("/").send().await;

        resp.assert_status_is_ok();
        resp.assert_header("X-Content-Type-Options", "nosniff");
        resp.assert_header("X-Frame-Options", "SAMEORIGIN");
        resp.assert_header("X-XSS-Protection", "1; mode=block");
    }

    #[tokio::test]
    async fn test_helmet_default() {
        let mw: HelmetMiddleware = Helmet::default().try_into().unwrap();
        let app = Route::new().at("/", index).with(mw);

        let client = TestClient::new(app);
        let resp = client.get("/").send().await;

        resp.assert_status_is_ok();
        resp.assert_header("X-Frame-Options", "SAMEORIGIN");
        resp.assert_header("X-XSS-Protection", "0");
        resp.assert_header("Referrer-Policy", "no-referrer");
    }
}
