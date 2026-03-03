//! `rocket-helmet` is a security middleware for the Rocket web framework that sets various HTTP headers to help protect your app.
//!
//! `rocket_helmet::Helmet` is a [Fairing](https://rocket.rs/guide/v0.5/fairings/) that automatically sets security headers on all responses.
//!
//! It is based on the [Helmet](https://helmetjs.github.io/) library for Node.js and is highly configurable.
//!
//! # Usage
//!
//! ```no_run
//! #[macro_use] extern crate rocket;
//!
//! use rocket_helmet::Helmet;
//!
//! #[get("/")]
//! fn index() -> &'static str {
//!     "Hello, world!"
//! }
//!
//! #[launch]
//! fn rocket() -> _ {
//!     rocket::build()
//!         .attach(Helmet::default())
//!         .mount("/", routes![index])
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
//! #[macro_use] extern crate rocket;
//!
//! use rocket_helmet::{Helmet, ContentSecurityPolicy, CrossOriginOpenerPolicy};
//!
//! #[get("/")]
//! fn index() -> &'static str {
//!     "Hello, world!"
//! }
//!
//! #[launch]
//! fn rocket() -> _ {
//!     rocket::build()
//!         .attach(
//!             Helmet::new()
//!                 .add(
//!                     ContentSecurityPolicy::new()
//!                         .default_src(vec!["'self'"])
//!                         .script_src(vec!["'self'", "https://cdn.example.com"]),
//!                 )
//!                 .add(CrossOriginOpenerPolicy::same_origin_allow_popups()),
//!         )
//!         .mount("/", routes![index])
//! }
//! ```
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Request, Response};

use helmet_core::Helmet as HelmetCore;

// re-export helmet_core::*, except for the `Helmet` struct
pub use helmet_core::*;

/// Helmet fairing that adds security headers to all responses.
///
/// Use `Helmet::default()` for a sensible set of default security headers,
/// or `Helmet::new()` to start with no headers and add only the ones you need.
///
/// ```rust
/// use rocket_helmet::Helmet;
///
/// let helmet = Helmet::default();
/// ```
#[derive(Default)]
pub struct Helmet(HelmetCore);

impl Helmet {
    /// Create a new instance of `Helmet` with no headers set.
    pub fn new() -> Self {
        Self(HelmetCore::new())
    }

    /// Add a header to the middleware.
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, middleware: impl Into<helmet_core::Header>) -> Self {
        Self(self.0.add(middleware))
    }
}

#[rocket::async_trait]
impl Fairing for Helmet {
    fn info(&self) -> Info {
        Info {
            name: "Helmet Security Headers",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, _req: &'r Request<'_>, res: &mut Response<'r>) {
        for (name, value) in &self.0.headers {
            res.set_header(rocket::http::Header::new(*name, value.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rocket::http::Status;
    use rocket::local::asynchronous::Client;
    use rocket::{get, routes};

    #[get("/")]
    fn index() -> &'static str {
        "Hello, world!"
    }

    #[rocket::async_test]
    async fn test_helmet() {
        let rocket = rocket::build()
            .attach(
                Helmet::new()
                    .add(helmet_core::XContentTypeOptions::nosniff())
                    .add(helmet_core::XFrameOptions::same_origin())
                    .add(helmet_core::XXSSProtection::on().mode_block()),
            )
            .mount("/", routes![index]);

        let client = Client::tracked(rocket).await.expect("valid rocket");
        let response = client.get("/").dispatch().await;

        assert_eq!(response.status(), Status::Ok);

        let headers = response.headers();
        assert_eq!(headers.get_one("X-Content-Type-Options"), Some("nosniff"));
        assert_eq!(headers.get_one("X-Frame-Options"), Some("SAMEORIGIN"));
        assert_eq!(headers.get_one("X-XSS-Protection"), Some("1; mode=block"));
    }

    #[rocket::async_test]
    async fn test_helmet_default() {
        let rocket = rocket::build()
            .attach(Helmet::default())
            .mount("/", routes![index]);

        let client = Client::tracked(rocket).await.expect("valid rocket");
        let response = client.get("/").dispatch().await;

        assert_eq!(response.status(), Status::Ok);

        let headers = response.headers();
        assert_eq!(headers.get_one("X-Frame-Options"), Some("SAMEORIGIN"));
        assert_eq!(headers.get_one("X-XSS-Protection"), Some("0"));
        assert_eq!(headers.get_one("Referrer-Policy"), Some("no-referrer"));
    }
}
