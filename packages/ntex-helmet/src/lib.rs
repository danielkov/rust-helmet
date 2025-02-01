//! `ntex-helmet`` is a collection of HTTP headers that help secure your ntex app by setting various HTTP headers.
//!
//! `ntex_helmet::Helmet`` is a middleware that automatically sets these headers.
//!
//! It is based on the [Helmet](https://helmetjs.github.io/) library for Node.js and is highly configurable.
//!
//! # Usage
//!
//! ```no_run
//! use ntex::web;
//! use ntex_helmet::Helmet;
//!
//! #[ntex::main]
//! async fn main() -> std::io::Result<()> {
//!     web::HttpServer::new(move || {
//!         web::App::new()
//!            .wrap(Helmet::default())
//!            .service(web::resource("/").to(|| async { "Hello, world!" }))
//!     })
//!     .bind(("127.0.0.1", 8080))?
//!     .run()
//!     .await
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
//! use ntex::web;
//! use ntex_helmet::{ContentSecurityPolicy, CrossOriginOpenerPolicy, Helmet};
//!
//! #[ntex::main]
//! async fn main() -> std::io::Result<()> {
//!     web::HttpServer::new(move || {
//!         web::App::new()
//!             .wrap(
//!                 Helmet::new()
//!                     .add(
//!                         ContentSecurityPolicy::new()
//!                             .child_src(vec!["'self'", "https://youtube.com"])
//!                             .connect_src(vec!["'self'", "https://youtube.com"])
//!                             .default_src(vec!["'self'", "https://youtube.com"])
//!                             .font_src(vec!["'self'", "https://youtube.com"]),
//!                     )
//!                     .add(CrossOriginOpenerPolicy::same_origin_allow_popups()),
//!             )
//!             .service(web::resource("/").to(|| async { "Hello, world!" }))
//!     })
//!     .bind(("127.0.0.1", 4200))?
//!     .run()
//!     .await
//! }
//! ```
use ntex::{
    forward_poll_ready, forward_poll_shutdown,
    http::{
        header::{HeaderName, HeaderValue},
        HeaderMap,
    },
    util::BoxFuture,
    web::{WebRequest, WebResponse},
    Middleware, Service, ServiceCtx,
};

use helmet_core::Helmet as HelmetCore;

// re-export helmet_core::*, except for the `Helmet` struct
pub use helmet_core::*;

pub struct HelmetMiddleware<S> {
    service: S,
    headers: HeaderMap,
}

impl<S, E> Service<WebRequest<E>> for HelmetMiddleware<S>
where
    S: Service<WebRequest<E>, Response = WebResponse>,
    E: 'static,
{
    type Response = WebResponse;
    type Error = S::Error;
    type Future<'f>
        = BoxFuture<'f, Result<Self::Response, Self::Error>>
    where
        S: 'f,
        E: 'f;

    forward_poll_ready!(service);
    forward_poll_shutdown!(service);

    fn call<'a>(&'a self, req: WebRequest<E>, ctx: ServiceCtx<'a, Self>) -> Self::Future<'a> {
        Box::pin(async move {
            let mut res = ctx.call(&self.service, req).await?;

            // set response headers
            for (name, value) in self.headers.iter() {
                res.headers_mut().append(name.clone(), value.clone());
            }

            Ok(res)
        })
    }
}

/// Helmet middleware
/// ```rust
/// use ntex::web;
/// use ntex_helmet::Helmet;
#[derive(Default)]
pub struct Helmet(HelmetCore);

#[allow(clippy::should_implement_trait)]
impl Helmet {
    pub fn new() -> Self {
        Self(HelmetCore::new())
    }

    pub fn add(self, middleware: impl helmet_core::Header + 'static) -> Self {
        Self(self.0.add(middleware))
    }
}

impl<S> Middleware<S> for Helmet {
    type Service = HelmetMiddleware<S>;

    fn create(&self, service: S) -> Self::Service {
        let mut headers = HeaderMap::new();
        for header in self.0.headers.iter() {
            let name = HeaderName::try_from(header.name()).expect("invalid header name");
            let value = HeaderValue::from_str(&header.value()).expect("invalid header value");
            headers.append(name, value);
        }

        HelmetMiddleware { service, headers }
    }
}

#[cfg(test)]
mod tests {
    use ntex::{
        web::test::{ok_service, TestRequest},
        Pipeline,
    };

    use helmet_core::{
        ContentSecurityPolicy, CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy,
        CrossOriginResourcePolicy, OriginAgentCluster, ReferrerPolicy, StrictTransportSecurity,
        XContentTypeOptions, XDNSPrefetchControl, XDownloadOptions, XFrameOptions,
        XPermittedCrossDomainPolicies, XPoweredBy, XXSSProtection,
    };

    use super::*;

    #[ntex::test]
    async fn test_cross_origin_embedder_policy_unsafe_none() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(CrossOriginEmbedderPolicy::unsafe_none())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Cross-Origin-Embedder-Policy").unwrap(),
            "unsafe-none"
        );
    }

    #[ntex::test]
    async fn test_cross_origin_embedder_policy_require_corp() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(CrossOriginEmbedderPolicy::require_corp())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Cross-Origin-Embedder-Policy").unwrap(),
            "require-corp"
        );
    }

    #[ntex::test]
    async fn test_cross_origin_embedder_policy_credentialless() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(CrossOriginEmbedderPolicy::credentialless())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Cross-Origin-Embedder-Policy").unwrap(),
            "credentialless"
        );
    }

    #[ntex::test]
    async fn test_cross_origin_opener_policy_same_origin() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(CrossOriginOpenerPolicy::same_origin())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Cross-Origin-Opener-Policy").unwrap(),
            "same-origin"
        );
    }

    #[ntex::test]
    async fn test_cross_origin_opener_policy_same_origin_allow_popups() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(CrossOriginOpenerPolicy::same_origin_allow_popups())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Cross-Origin-Opener-Policy").unwrap(),
            "same-origin-allow-popups"
        );
    }

    #[ntex::test]
    async fn test_cross_origin_opener_policy_unsafe_none() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(CrossOriginOpenerPolicy::unsafe_none())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Cross-Origin-Opener-Policy").unwrap(),
            "unsafe-none"
        );
    }

    #[ntex::test]
    async fn test_cross_origin_resource_policy_same_origin() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(CrossOriginResourcePolicy::same_origin())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Cross-Origin-Resource-Policy").unwrap(),
            "same-origin"
        );
    }

    #[ntex::test]
    async fn test_cross_origin_resource_policy_cross_origin() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(CrossOriginResourcePolicy::cross_origin())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Cross-Origin-Resource-Policy").unwrap(),
            "cross-origin"
        );
    }

    #[ntex::test]
    async fn test_cross_origin_resource_policy_same_site() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(CrossOriginResourcePolicy::same_site())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Cross-Origin-Resource-Policy").unwrap(),
            "same-site"
        );
    }

    #[ntex::test]
    async fn test_origin_agent_cluster_prefer_mobile() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(OriginAgentCluster::new(true))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("Origin-Agent-Cluster")
                .unwrap()
                .to_str()
                .unwrap(),
            "?1"
        );
    }

    #[ntex::test]
    async fn test_origin_agent_cluster_not_prefer_mobile() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(OriginAgentCluster::new(false))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("Origin-Agent-Cluster")
                .unwrap()
                .to_str()
                .unwrap(),
            "?0"
        );
    }

    #[ntex::test]
    async fn test_referrer_policy_no_referrer() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ReferrerPolicy::no_referrer())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Referrer-Policy").unwrap(),
            "no-referrer"
        );
    }

    #[ntex::test]
    async fn test_referrer_policy_no_referrer_when_downgrade() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ReferrerPolicy::no_referrer_when_downgrade())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Referrer-Policy").unwrap(),
            "no-referrer-when-downgrade"
        );
    }

    #[ntex::test]
    async fn test_referrer_policy_origin() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ReferrerPolicy::origin())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(resp.headers().get("Referrer-Policy").unwrap(), "origin");
    }

    #[ntex::test]
    async fn test_referrer_policy_origin_when_cross_origin() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ReferrerPolicy::origin_when_cross_origin())
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Referrer-Policy").unwrap(),
            "origin-when-cross-origin"
        );
    }

    #[ntex::test]
    async fn test_referrer_policy_same_origin() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ReferrerPolicy::same_origin())
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Referrer-Policy").unwrap(),
            "same-origin"
        );
    }

    #[ntex::test]
    async fn test_referrer_policy_strict_origin() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ReferrerPolicy::strict_origin())
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Referrer-Policy").unwrap(),
            "strict-origin"
        );
    }

    #[ntex::test]
    async fn test_referrer_policy_strict_origin_when_cross_origin() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ReferrerPolicy::strict_origin_when_cross_origin())
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Referrer-Policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
    }

    #[ntex::test]
    async fn test_referrer_policy_unsafe_url() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ReferrerPolicy::unsafe_url())
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(resp.headers().get("Referrer-Policy").unwrap(), "unsafe-url");
    }

    #[ntex::test]
    async fn test_strict_transport_security_max_age() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(StrictTransportSecurity::new().max_age(31536000))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Strict-Transport-Security")
                .unwrap()
                .to_str()
                .unwrap(),
            "max-age=31536000"
        );
    }

    #[ntex::test]
    async fn test_strict_transport_security_max_age_include_sub_domains() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    StrictTransportSecurity::new()
                        .max_age(31536000)
                        .include_sub_domains(),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Strict-Transport-Security")
                .unwrap()
                .to_str()
                .unwrap(),
            "max-age=31536000; includeSubDomains"
        );
    }

    #[ntex::test]
    async fn test_strict_transport_security_max_age_preload() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(StrictTransportSecurity::new().max_age(31536000).preload())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Strict-Transport-Security")
                .unwrap()
                .to_str()
                .unwrap(),
            "max-age=31536000; preload"
        );
    }

    #[ntex::test]
    async fn test_strict_transport_security_max_age_include_sub_domains_preload() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    StrictTransportSecurity::new()
                        .max_age(31536000)
                        .include_sub_domains()
                        .preload(),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Strict-Transport-Security")
                .unwrap()
                .to_str()
                .unwrap(),
            "max-age=31536000; includeSubDomains; preload"
        );
    }

    #[ntex::test]
    async fn test_x_content_type_options_nosniff() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XContentTypeOptions::nosniff())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("X-Content-Type-Options")
                .unwrap()
                .to_str()
                .unwrap(),
            "nosniff"
        );
    }

    #[ntex::test]
    async fn test_x_dns_prefetch_control_off() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XDNSPrefetchControl::off())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("X-DNS-Prefetch-Control")
                .unwrap()
                .to_str()
                .unwrap(),
            "off"
        );
    }

    #[ntex::test]
    async fn test_x_dns_prefetch_control_on() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XDNSPrefetchControl::on())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("X-DNS-Prefetch-Control")
                .unwrap()
                .to_str()
                .unwrap(),
            "on"
        );
    }

    #[ntex::test]
    async fn test_x_download_options_noopen() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XDownloadOptions::noopen())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("X-Download-Options")
                .unwrap()
                .to_str()
                .unwrap(),
            "noopen"
        );
    }

    #[ntex::test]
    async fn test_x_frame_options_deny() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XFrameOptions::deny())
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("X-Frame-Options")
                .unwrap()
                .to_str()
                .unwrap(),
            "DENY"
        );
    }

    #[ntex::test]
    async fn test_x_frame_options_same_origin() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XFrameOptions::same_origin())
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("X-Frame-Options")
                .unwrap()
                .to_str()
                .unwrap(),
            "SAMEORIGIN"
        );
    }

    #[ntex::test]
    async fn test_x_frame_options_allow_from() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XFrameOptions::allow_from("https://example.com"))
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("X-Frame-Options")
                .unwrap()
                .to_str()
                .unwrap(),
            "ALLOW-FROM https://example.com"
        );
    }

    #[ntex::test]
    async fn test_x_permitted_cross_domain_policies_none() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XPermittedCrossDomainPolicies::none())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("X-Permitted-Cross-Domain-Policies")
                .unwrap()
                .to_str()
                .unwrap(),
            "none"
        );
    }

    #[ntex::test]
    async fn test_x_permitted_cross_domain_policies_master_only() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XPermittedCrossDomainPolicies::master_only())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("X-Permitted-Cross-Domain-Policies")
                .unwrap()
                .to_str()
                .unwrap(),
            "master-only"
        );
    }

    #[ntex::test]
    async fn test_x_permitted_cross_domain_policies_by_content_type() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XPermittedCrossDomainPolicies::by_content_type())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("X-Permitted-Cross-Domain-Policies")
                .unwrap()
                .to_str()
                .unwrap(),
            "by-content-type"
        );
    }

    #[ntex::test]
    async fn test_x_permitted_cross_domain_policies_by_ftp_filename() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XPermittedCrossDomainPolicies::by_ftp_filename())
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("X-Permitted-Cross-Domain-Policies")
                .unwrap()
                .to_str()
                .unwrap(),
            "by-ftp-filename"
        );
    }

    #[ntex::test]
    async fn test_x_permitted_cross_domain_policies_all() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XPermittedCrossDomainPolicies::all())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("X-Permitted-Cross-Domain-Policies")
                .unwrap()
                .to_str()
                .unwrap(),
            "all"
        );
    }

    #[ntex::test]
    async fn test_x_xss_protection_zero() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XXSSProtection::off())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(resp.headers().get("X-XSS-Protection").unwrap(), "0");
    }

    #[ntex::test]
    async fn test_x_xss_protection_one() {
        let mw = Pipeline::new(Helmet::new().add(XXSSProtection::on()).create(ok_service()));

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(resp.headers().get("X-XSS-Protection").unwrap(), "1");
    }

    #[ntex::test]
    async fn test_x_xss_protection_one_mode_block() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XXSSProtection::on().mode_block())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers().get("X-XSS-Protection").unwrap(),
            "1; mode=block"
        );
    }

    #[ntex::test]
    async fn test_x_xss_protection_one_mode_block_report() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    XXSSProtection::on()
                        .mode_block()
                        .report("https://example.com/report-xss-attack"),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("X-XSS-Protection")
                .unwrap()
                .to_str()
                .unwrap(),
            "1; mode=block; report=https://example.com/report-xss-attack"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_default() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::default())
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests"
        );
    }

    #[ntex::test]
    async fn test_x_powered_by() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(XPoweredBy::new("PHP 4.2.0"))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(resp.headers().get("X-Powered-By").unwrap(), "PHP 4.2.0");
    }

    #[ntex::test]
    async fn test_content_security_policy_child_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().child_src(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "child-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_connect_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new().connect_src(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "connect-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_default_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new().default_src(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "default-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_font_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().font_src(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "font-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_frame_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().frame_src(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "frame-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_img_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().img_src(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "img-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_manifest_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new()
                        .manifest_src(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "manifest-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_media_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().media_src(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "media-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_object_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().object_src(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "object-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_prefetch_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new()
                        .prefetch_src(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "prefetch-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_script_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().script_src(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "script-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_script_src_elem() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new()
                        .script_src_elem(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "script-src-elem 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_script_src_attr() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new()
                        .script_src_attr(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "script-src-attr 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_style_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().style_src(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "style-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_style_src_attr() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new()
                        .style_src_attr(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "style-src-attr 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_style_src_elem() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new()
                        .style_src_elem(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "style-src-elem 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_worker_src() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().worker_src(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "worker-src 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_base_uri() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().base_uri(vec!["'self'", "https://youtube.com"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "base-uri 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_sandbox() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().sandbox(vec!["allow-forms", "allow-scripts"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "sandbox allow-forms allow-scripts"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_form_action() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new().form_action(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "form-action 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_frame_ancestors() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new()
                        .frame_ancestors(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default()
            .header("Origin", "https://example.com")
            .to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "frame-ancestors 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_report_to() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().report_to(vec!["default", "endpoint", "group"]))
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "report-to default endpoint group; report-uri default endpoint group"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_trusted_types() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new()
                        .trusted_types(vec!["'self'", "https://youtube.com"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "trusted-types 'self' https://youtube.com"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_require_trusted_types_for() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new().require_trusted_types_for(vec!["script", "style"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "require-trusted-types-for script style"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_upgrade_insecure_requests() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(ContentSecurityPolicy::new().upgrade_insecure_requests())
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();
        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "upgrade-insecure-requests"
        );
    }

    #[ntex::test]
    async fn test_helmet_default() {
        let mw = Pipeline::new(Helmet::default().create(ok_service()));

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert_eq!(
            resp.headers().get("Content-Security-Policy").unwrap(),
            "default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests"
        );
        assert_eq!(
            resp.headers().get("Cross-Origin-Opener-Policy").unwrap(),
            "same-origin"
        );
        assert_eq!(
            resp.headers().get("Cross-Origin-Resource-Policy").unwrap(),
            "same-origin"
        );
        assert_eq!(resp.headers().get("Origin-Agent-Cluster").unwrap(), "?1");
        assert_eq!(
            resp.headers().get("Referrer-Policy").unwrap(),
            "no-referrer"
        );
        assert_eq!(
            resp.headers().get("Strict-Transport-Security").unwrap(),
            "max-age=15552000; includeSubDomains"
        );
        assert_eq!(
            resp.headers().get("X-Content-Type-Options").unwrap(),
            "nosniff"
        );
        assert_eq!(resp.headers().get("X-DNS-Prefetch-Control").unwrap(), "off");
        assert_eq!(resp.headers().get("X-Download-Options").unwrap(), "noopen");
        assert_eq!(resp.headers().get("X-Frame-Options").unwrap(), "SAMEORIGIN");
        assert_eq!(
            resp.headers()
                .get("X-Permitted-Cross-Domain-Policies")
                .unwrap(),
            "none"
        );
    }

    #[ntex::test]
    async fn test_content_security_policy_report_only() {
        let mw = Pipeline::new(
            Helmet::new()
                .add(
                    ContentSecurityPolicy::new()
                        .report_only()
                        .base_uri(vec!["'self'"]),
                )
                .create(ok_service()),
        );

        let req = TestRequest::default().to_srv_request();
        let resp = mw.call(req).await.unwrap();

        assert!(resp.headers().get("Content-Security-Policy").is_none());

        assert_eq!(
            resp.headers()
                .get("Content-Security-Policy-Report-Only")
                .unwrap()
                .to_str()
                .unwrap(),
            "base-uri 'self'"
        );
    }
}
