//! `salvo-helmet` is a security middleware for the Salvo web framework that sets various HTTP headers to help protect your app.
//!
//! `salvo_helmet::Helmet` is a handler that automatically sets security headers on all responses.
//!
//! It is based on the [Helmet](https://helmetjs.github.io/) library for Node.js and is highly configurable.
//!
//! # Usage
//!
//! ```no_run
//! use salvo::prelude::*;
//! use salvo_helmet::{Helmet, HelmetHandler};
//!
//! #[handler]
//! async fn index() -> &'static str {
//!     "Hello, world!"
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let handler: HelmetHandler = Helmet::default().try_into().unwrap();
//!     let router = Router::with_hoop(handler).get(index);
//!
//!     let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;
//!     Server::new(acceptor).serve(router).await;
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
//! It is possible to configure `Helmet` to set only the headers you want, by using the `add` method.
//!
//! ```no_run
//! use salvo::prelude::*;
//! use salvo_helmet::{Helmet, HelmetHandler, ContentSecurityPolicy, CrossOriginOpenerPolicy};
//!
//! #[handler]
//! async fn index() -> &'static str {
//!     "Hello, world!"
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let handler: HelmetHandler = Helmet::new()
//!         .add(
//!             ContentSecurityPolicy::new()
//!                 .default_src(vec!["'self'"])
//!                 .script_src(vec!["'self'", "https://cdn.example.com"]),
//!         )
//!         .add(CrossOriginOpenerPolicy::same_origin_allow_popups())
//!         .try_into()
//!         .unwrap();
//!
//!     let router = Router::with_hoop(handler).get(index);
//!
//!     let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;
//!     Server::new(acceptor).serve(router).await;
//! }
//! ```
use http::header::{HeaderMap, HeaderName, HeaderValue};
use salvo::handler::Handler;
use salvo::{async_trait, Depot, FlowCtrl, Request, Response};

use helmet_core::Helmet as HelmetCore;

// re-export helmet_core::*, except for the `Helmet` struct
pub use helmet_core::*;

/// Helmet header configuration wrapper.
///
/// Use `Helmet::default()` for a sensible set of default security headers,
/// or `Helmet::new()` to start with no headers and add only the ones you need.
///
/// Convert to [`HelmetHandler`] via `try_into()` to use as a Salvo hoop.
///
/// ```rust
/// use salvo_helmet::{Helmet, HelmetHandler};
///
/// let handler: HelmetHandler = Helmet::default().try_into().unwrap();
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

    pub fn into_handler(self) -> Result<HelmetHandler, HelmetError> {
        self.try_into()
    }
}

/// The Salvo handler created by converting a [`Helmet`] configuration.
pub struct HelmetHandler {
    headers: HeaderMap,
}

impl TryFrom<Helmet> for HelmetHandler {
    type Error = HelmetError;

    fn try_from(helmet: Helmet) -> Result<Self, Self::Error> {
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

#[async_trait]
impl Handler for HelmetHandler {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        ctrl.call_next(req, depot, res).await;
        for (name, value) in self.headers.iter() {
            res.headers_mut().insert(name.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::prelude::*;
    use salvo::test::TestClient;

    #[handler]
    async fn index() -> &'static str {
        "Hello, world!"
    }

    #[tokio::test]
    async fn test_helmet() {
        let router = Router::with_hoop(
            Helmet::new()
                .add(helmet_core::XContentTypeOptions::nosniff())
                .add(helmet_core::XFrameOptions::same_origin())
                .add(helmet_core::XXSSProtection::on().mode_block())
                .into_handler()
                .unwrap(),
        )
        .get(index);
        let service = Service::new(router);

        let res = TestClient::get("http://localhost/").send(&service).await;

        assert_eq!(res.status_code, Some(StatusCode::OK));
        assert_eq!(
            res.headers()
                .get("X-Content-Type-Options")
                .map(|v| v.to_str().unwrap()),
            Some("nosniff")
        );
        assert_eq!(
            res.headers()
                .get("X-Frame-Options")
                .map(|v| v.to_str().unwrap()),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            res.headers()
                .get("X-XSS-Protection")
                .map(|v| v.to_str().unwrap()),
            Some("1; mode=block")
        );
    }

    #[tokio::test]
    async fn test_helmet_default() {
        let handler: HelmetHandler = Helmet::default().try_into().unwrap();
        let router = Router::with_hoop(handler).get(index);
        let service = Service::new(router);

        let res = TestClient::get("http://localhost/").send(&service).await;

        assert_eq!(res.status_code, Some(StatusCode::OK));
        assert_eq!(
            res.headers()
                .get("X-Frame-Options")
                .map(|v| v.to_str().unwrap()),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            res.headers()
                .get("X-XSS-Protection")
                .map(|v| v.to_str().unwrap()),
            Some("0")
        );
        assert_eq!(
            res.headers()
                .get("Referrer-Policy")
                .map(|v| v.to_str().unwrap()),
            Some("no-referrer")
        );
    }
}
