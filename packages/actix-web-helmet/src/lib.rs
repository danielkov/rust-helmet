//! `actix-web-helmet` is a middleware for securing your Actix-Web application with various HTTP headers.
//!
//! `actix_web_helmet::Helmet` is a middleware that can be used to set various HTTP headers that can help protect your app from well-known web vulnerabilities.
//!
//! It is based on the [Helmet](https://helmetjs.github.io/) middleware for Express.js.
//!
//! # Usage
//!
//! ```no_run
//! use actix_web::{web, App, HttpServer, Responder, get};
//! use actix_web_helmet::Helmet;
//!
//! #[get("/")]
//! async fn index() -> impl Responder {
//!   "Hello, World!"
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!  HttpServer::new(|| App::new().wrap(Helmet::default()).service(index))
//!      .bind(("127.0.0.1", 8080))?
//!      .run()
//!      .await
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
//! use actix_web::{get, web, App, HttpServer, Responder};
//! use actix_web_helmet::{Helmet, ContentSecurityPolicy, CrossOriginOpenerPolicy};
//!
//! #[get("/")]
//! async fn index() -> impl Responder {
//!     "Hello, World!"
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     HttpServer::new(|| {
//!         {
//!             App::new().wrap(
//!                 Helmet::new()
//!                     .add(
//!                         ContentSecurityPolicy::new()
//!                             .child_src(vec!["'self'"])
//!                             .child_src(vec!["'self'", "https://youtube.com"])
//!                             .connect_src(vec!["'self'", "https://youtube.com"])
//!                             .default_src(vec!["'self'", "https://youtube.com"])
//!                             .font_src(vec!["'self'", "https://youtube.com"]),
//!                     )
//!                     .add(CrossOriginOpenerPolicy::same_origin_allow_popups()),
//!             )
//!         }
//!         .service(index)
//!     })
//!     .bind(("127.0.0.1", 8080))?
//!     .run()
//!     .await
//! }
//! ```
use std::future::Future;
use std::pin::Pin;

use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::Error;
use futures::future::{ok, Ready};

use helmet_core::Helmet as HelmetCore;

// re-export helmet_core::*, except for the `Helmet` struct
pub use helmet_core::*;

pub struct HelmetMiddleware<S> {
    inner: HelmetCore,
    service: S,
}

/// Helmet middleware
/// ```rust
/// use actix_web::{web, App, HttpServer};
/// use actix_web_helmet::Helmet;
/// ```
pub struct Helmet(HelmetCore);

impl Helmet {
    /// Create a new instance of `Helmet` with no headers set.
    pub fn new() -> Self {
        Self(HelmetCore::new())
    }

    /// Add a header to the middleware.
    pub fn add(self, middleware: impl Into<helmet_core::Header>) -> Self {
        Self(self.0.add(middleware))
    }
}

impl<S, B> Transform<S, ServiceRequest> for Helmet
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static, // Add 'static bound
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    // The actual middleware service that will be created
    type Transform = HelmetMiddleware<S>;
    // The future that resolves to the middleware service
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        // Create the middleware service instance HelmetMiddleware
        // Clone the inner configuration (HelmetCore).
        // HelmetCore should derive Clone or you might need to wrap it in Rc/Arc.
        // Assuming HelmetCore is Clone:
        ok(HelmetMiddleware {
            inner: self.0.clone(), // Clone the configuration from the factory
            service,               // Pass the next service in the chain
        })

        // If HelmetCore is large and not Clone, you might wrap it in Rc in the Helmet struct:
        // pub struct Helmet(Rc<HelmetCore>);
        // And then clone the Rc here:
        // ok(HelmetMiddleware {
        //     inner: self.0.clone(),
        //     service,
        // })
    }
}

impl Default for Helmet {
    fn default() -> Self {
        Self(HelmetCore::default())
    }
}

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + 'static>>;

impl<S, B> Service<ServiceRequest> for HelmetMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<Result<Self::Response, Self::Error>>;

    // This service is ready when its next service is ready
    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);

        let headers_vec = self
            .inner
            .headers
            .iter()
            .map(|header| (header.0, header.1.clone()))
            .collect::<Vec<_>>();

        Box::pin(async move {
            let mut res = fut.await?;

            // Set the headers
            for (name, value) in &headers_vec {
                res.headers_mut().insert(
                    HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_str(value).unwrap(),
                );
            }
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::header::{HeaderName, HeaderValue};
    // Make sure HttpResponse is imported if not already
    use actix_web::{http, test, web, App, HttpResponse}; // Added test, http, HttpResponse

    use super::*; // Keep this

    #[actix_web::test]
    async fn test_helmet() {
        // 1. Create the middleware *factory* instance
        let helmet_factory =
            Helmet::new().add(ContentSecurityPolicy::new().child_src(vec!["'self'"]));

        // 2. Initialize the service using the factory with .wrap()
        let app = test::init_service(
            // Use test::init_service
            App::new()
                .wrap(helmet_factory) // Use the factory here
                // Define a simple async route correctly
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        // 3. Create a request
        let req = test::TestRequest::get().uri("/").to_request(); // Use test::TestRequest

        // 4. Call the service
        let res = test::call_service(&app, req).await; // Use test::call_service and the app

        // 5. Assertions
        assert!(res.status().is_success()); // Check status code idiomatically
        assert_eq!(
            res.headers()
                .get(HeaderName::from_static("content-security-policy")),
            Some(&HeaderValue::from_static("child-src 'self'"))
        );
    }

    // Optional: Add a test for the default configuration
    #[actix_web::test]
    async fn test_helmet_default() {
        let app = test::init_service(
            App::new()
                .wrap(Helmet::default()) // Use the default factory
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        // Check one or two default headers to confirm it works
        assert_eq!(
            resp.headers().get(http::header::X_FRAME_OPTIONS), // Use constants from http::header
            Some(&HeaderValue::from_static("SAMEORIGIN"))
        );
        assert_eq!(
            resp.headers().get(http::header::X_XSS_PROTECTION),
            Some(&HeaderValue::from_static("0"))
        );
    }
}
