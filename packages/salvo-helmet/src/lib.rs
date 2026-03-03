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
//! use salvo_helmet::Helmet;
//!
//! #[handler]
//! async fn index() -> &'static str {
//!     "Hello, world!"
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let router = Router::with_hoop(Helmet::default())
//!         .get(index);
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
//! It is possible to configure `Helmet` to set only the headers you want, by using the `add` method to add headers.
//!
//! ```no_run
//! use salvo::prelude::*;
//! use salvo_helmet::{Helmet, ContentSecurityPolicy, CrossOriginOpenerPolicy};
//!
//! #[handler]
//! async fn index() -> &'static str {
//!     "Hello, world!"
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let router = Router::with_hoop(
//!             Helmet::new()
//!                 .add(
//!                     ContentSecurityPolicy::new()
//!                         .default_src(vec!["'self'"])
//!                         .script_src(vec!["'self'", "https://cdn.example.com"]),
//!                 )
//!                 .add(CrossOriginOpenerPolicy::same_origin_allow_popups()),
//!         )
//!         .get(index);
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

/// Helmet handler for Salvo.
///
/// Use `Helmet::default()` for a sensible set of default security headers,
/// or `Helmet::new()` to start with no headers and add only the ones you need.
///
/// Apply as a hoop (middleware) on a router:
///
/// ```rust
/// use salvo::prelude::*;
/// use salvo_helmet::Helmet;
///
/// let router = Router::with_hoop(Helmet::default());
/// ```
pub struct Helmet {
    headers: HeaderMap,
}

impl Default for Helmet {
    fn default() -> Self {
        Self::from(HelmetCore::default())
    }
}

impl Helmet {
    /// Create a new instance of `Helmet` with no headers set.
    pub fn new() -> Self {
        Self::from(HelmetCore::new())
    }

    /// Add a header to the middleware.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, header: impl Into<helmet_core::Header>) -> Self {
        let header = header.into();
        let name = HeaderName::try_from(header.0).expect("invalid header name");
        let value = HeaderValue::from_str(&header.1).expect("invalid header value");
        self.headers.append(name, value);
        self
    }
}

impl From<HelmetCore> for Helmet {
    fn from(core: HelmetCore) -> Self {
        let headers = core
            .headers
            .iter()
            .map(|header| {
                (
                    HeaderName::try_from(header.0).expect("invalid header name"),
                    HeaderValue::from_str(&header.1).expect("invalid header value"),
                )
            })
            .collect();
        Self { headers }
    }
}

#[async_trait]
impl Handler for Helmet {
    async fn handle(
        &self,
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        ctrl.call_next(req, depot, res).await;
        res.headers_mut()
            .extend(self.headers.iter().map(|(k, v)| (k.clone(), v.clone())));
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
                .add(helmet_core::XXSSProtection::on().mode_block()),
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
        let router = Router::with_hoop(Helmet::default()).get(index);
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
