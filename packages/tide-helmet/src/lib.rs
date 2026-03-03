//! `tide-helmet` is a security middleware for the Tide web framework that sets various HTTP headers to help protect your app.
//!
//! `tide_helmet::Helmet` is a middleware that automatically sets security headers on all responses.
//!
//! It is based on the [Helmet](https://helmetjs.github.io/) library for Node.js and is highly configurable.
//!
//! # Usage
//!
//! ```no_run
//! use tide_helmet::Helmet;
//!
//! #[async_std::main]
//! async fn main() -> tide::Result<()> {
//!     let mut app = tide::new();
//!     app.with(Helmet::default());
//!     app.at("/").get(|_| async { Ok("Hello, world!") });
//!     app.listen("0.0.0.0:3000").await?;
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
//! use tide_helmet::{Helmet, ContentSecurityPolicy, CrossOriginOpenerPolicy};
//!
//! #[async_std::main]
//! async fn main() -> tide::Result<()> {
//!     let mut app = tide::new();
//!     app.with(
//!         Helmet::new()
//!             .add(
//!                 ContentSecurityPolicy::new()
//!                     .default_src(vec!["'self'"])
//!                     .script_src(vec!["'self'", "https://cdn.example.com"]),
//!             )
//!             .add(CrossOriginOpenerPolicy::same_origin_allow_popups()),
//!     );
//!     app.at("/").get(|_| async { Ok("Hello, world!") });
//!     app.listen("0.0.0.0:3000").await?;
//!     Ok(())
//! }
//! ```
use tide::{Middleware, Next, Request};

use helmet_core::Helmet as HelmetCore;

// re-export helmet_core::*, except for the `Helmet` struct
pub use helmet_core::*;

/// Helmet middleware for Tide.
///
/// Use `Helmet::default()` for a sensible set of default security headers,
/// or `Helmet::new()` to start with no headers and add only the ones you need.
///
/// ```rust
/// use tide_helmet::Helmet;
///
/// let mut app = tide::new();
/// app.with(Helmet::default());
/// ```
#[derive(Clone, Debug)]
pub struct Helmet {
    headers: Vec<(&'static str, String)>,
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
        self.headers.push(header.into());
        self
    }
}

impl From<HelmetCore> for Helmet {
    fn from(core: HelmetCore) -> Self {
        Self {
            headers: core
                .headers
                .iter()
                .map(|header| (header.0, header.1.clone()))
                .collect(),
        }
    }
}

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for Helmet {
    async fn handle(&self, req: Request<State>, next: Next<'_, State>) -> tide::Result {
        let mut res = next.run(req).await;
        for (name, value) in &self.headers {
            res.insert_header(*name, value.as_str());
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn test_helmet() {
        let mut app = tide::new();
        app.with(
            Helmet::new()
                .add(helmet_core::XContentTypeOptions::nosniff())
                .add(helmet_core::XFrameOptions::same_origin())
                .add(helmet_core::XXSSProtection::on().mode_block()),
        );
        app.at("/").get(|_| async { Ok("Hello, world!") });

        let req = tide::http::Request::new(
            tide::http::Method::Get,
            tide::http::Url::parse("http://localhost/").unwrap(),
        );
        let res: tide::http::Response = app.respond(req).await.unwrap();

        assert_eq!(res.status(), tide::StatusCode::Ok);
        assert_eq!(
            res.header("X-Content-Type-Options").map(|v| v.as_str()),
            Some("nosniff")
        );
        assert_eq!(
            res.header("X-Frame-Options").map(|v| v.as_str()),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            res.header("X-XSS-Protection").map(|v| v.as_str()),
            Some("1; mode=block")
        );
    }

    #[async_std::test]
    async fn test_helmet_default() {
        let mut app = tide::new();
        app.with(Helmet::default());
        app.at("/").get(|_| async { Ok("Hello, world!") });

        let req = tide::http::Request::new(
            tide::http::Method::Get,
            tide::http::Url::parse("http://localhost/").unwrap(),
        );
        let res: tide::http::Response = app.respond(req).await.unwrap();

        assert_eq!(res.status(), tide::StatusCode::Ok);
        assert_eq!(
            res.header("X-Frame-Options").map(|v| v.as_str()),
            Some("SAMEORIGIN")
        );
        assert_eq!(
            res.header("X-XSS-Protection").map(|v| v.as_str()),
            Some("0")
        );
        assert_eq!(
            res.header("Referrer-Policy").map(|v| v.as_str()),
            Some("no-referrer")
        );
    }
}
