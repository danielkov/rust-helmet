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
//! use actix_web_helmet::{Helmet, HelmetMiddleware};
//!
//! #[get("/")]
//! async fn index() -> impl Responder {
//!   "Hello, World!"
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!  let helmet: HelmetMiddleware = Helmet::default().try_into().expect("valid headers");
//!  HttpServer::new(move || App::new().wrap(helmet.clone()).service(index))
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
//! It is possible to configure `Helmet` to set only the headers you want, by using the `add` method.
//!
//! ```no_run
//! use actix_web::{get, web, App, HttpServer, Responder};
//! use actix_web_helmet::{Helmet, HelmetMiddleware, ContentSecurityPolicy, CrossOriginOpenerPolicy};
//!
//! #[get("/")]
//! async fn index() -> impl Responder {
//!     "Hello, World!"
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let helmet: HelmetMiddleware = Helmet::new()
//!         .add(
//!             ContentSecurityPolicy::new()
//!                 .child_src(vec!["'self'"])
//!                 .child_src(vec!["'self'", "https://youtube.com"])
//!                 .connect_src(vec!["'self'", "https://youtube.com"])
//!                 .default_src(vec!["'self'", "https://youtube.com"])
//!                 .font_src(vec!["'self'", "https://youtube.com"]),
//!         )
//!         .add(CrossOriginOpenerPolicy::same_origin_allow_popups())
//!         .try_into()
//!         .expect("valid headers");
//!
//!     HttpServer::new(move || {
//!         App::new().wrap(helmet.clone()).service(index)
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

/// Helmet header configuration wrapper.
///
/// Use `Helmet::default()` for a sensible set of default security headers,
/// or `Helmet::new()` to start with no headers and add only the ones you need.
///
/// Convert to [`HelmetMiddleware`] via `try_into()` to use as actix-web middleware.
///
/// ```rust
/// use actix_web_helmet::{Helmet, HelmetMiddleware};
///
/// let mw: HelmetMiddleware = Helmet::default().try_into().unwrap();
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

    pub fn into_middleware(self) -> Result<HelmetMiddleware, HelmetError> {
        self.try_into()
    }
}

/// The actix-web middleware created by converting a [`Helmet`] configuration.
#[derive(Clone)]
pub struct HelmetMiddleware {
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl TryFrom<Helmet> for HelmetMiddleware {
    type Error = HelmetError;

    fn try_from(helmet: Helmet) -> Result<Self, Self::Error> {
        let mut headers = Vec::new();
        for header in helmet.0.headers.iter() {
            let name = HeaderName::from_bytes(header.0.as_bytes())
                .map_err(|_| HelmetError::InvalidHeaderName(header.0.to_string()))?;
            let value = HeaderValue::from_str(&header.1)
                .map_err(|_| HelmetError::InvalidHeaderValue(header.1.clone()))?;
            headers.push((name, value));
        }
        Ok(Self { headers })
    }
}

pub struct HelmetService<S> {
    headers: Vec<(HeaderName, HeaderValue)>,
    service: S,
}

impl<S, B> Transform<S, ServiceRequest> for HelmetMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = HelmetService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(HelmetService {
            headers: self.headers.clone(),
            service,
        })
    }
}

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + 'static>>;

impl<S, B> Service<ServiceRequest> for HelmetService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        let headers = self.headers.clone();

        Box::pin(async move {
            let mut res = fut.await?;

            for (name, value) in &headers {
                res.headers_mut().insert(name.clone(), value.clone());
            }
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::header::{HeaderName, HeaderValue};
    use actix_web::{http, test, web, App, HttpResponse};

    use super::*;

    #[actix_web::test]
    async fn test_helmet() {
        let app = test::init_service(
            App::new()
                .wrap(
                    Helmet::new()
                        .add(ContentSecurityPolicy::new().child_src(vec!["'self'"]))
                        .into_middleware()
                        .unwrap(),
                )
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert!(res.status().is_success());
        assert_eq!(
            res.headers()
                .get(HeaderName::from_static("content-security-policy")),
            Some(&HeaderValue::from_static("child-src 'self'"))
        );
    }

    #[actix_web::test]
    async fn test_helmet_default() {
        let helmet: HelmetMiddleware = Helmet::default().try_into().unwrap();

        let app = test::init_service(
            App::new()
                .wrap(helmet)
                .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
        )
        .await;

        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        assert_eq!(
            resp.headers().get(http::header::X_FRAME_OPTIONS),
            Some(&HeaderValue::from_static("SAMEORIGIN"))
        );
        assert_eq!(
            resp.headers().get(http::header::X_XSS_PROTECTION),
            Some(&HeaderValue::from_static("0"))
        );
    }
}
