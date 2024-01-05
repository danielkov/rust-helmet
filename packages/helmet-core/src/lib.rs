//! Helmet is a collection of HTTP headers that help secure your app by setting various HTTP headers.
//!
//! `helmet-core` provides the core functionality of Helmet, vie convenient builders to configure the library.
//!
//! The library can be adapted to different frameworks by wrapping the `Helmet` struct in a way that suits the framework. For reference implementations see the [ntex-helmet](https://crates.io/crates/ntex-helmet) crate or the [axum-helmet](https://crates.io/crates/axum-helmet) crate.
//!
//! It is based on the [Helmet](https://helmetjs.github.io/) library for Node.js and is highly configurable.
//!
//! # Usage
//!
//! ```no_run
//! use helmet_core::{ContentSecurityPolicy, CrossOriginOpenerPolicy, Helmet};
//!
//! let helmet = Helmet::new()
//!     .add(
//!         ContentSecurityPolicy::new()
//!             .child_src(vec!["'self'", "https://youtube.com"])
//!             .connect_src(vec!["'self'", "https://youtube.com"])
//!             .default_src(vec!["'self'", "https://youtube.com"])
//!             .font_src(vec!["'self'", "https://youtube.com"]),
//!     )
//!     .add(CrossOriginOpenerPolicy::same_origin_allow_popups());
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
//! The `helmet-core` crate helps you configure Helmet by providing convenient builders for each header.
use core::fmt::Display;

/// Header trait
///
/// Allows custom headers to be added to the response
///
/// # Examples
///
/// ```
/// use helmet_core::Header;
///
/// struct MyHeader;
///
/// impl Header for MyHeader {
///    fn name(&self) -> &'static str {
///       "My-Header"
///   }
///
///   fn value(&self) -> String {
///      "my-value".to_string()
///  }
/// }
/// ```
pub trait Header {
    fn name(&self) -> &'static str;
    fn value(&self) -> String;
}

/// Manages `Cross-Origin-Embedder-Policy` header
///
/// The Cross-Origin-Embedder-Policy HTTP response header prevents a document from loading any cross-origin resources that do not explicitly grant the document permission (via CORS headers) to load them.
///
/// # Values
///
/// - unsafe-none: The document is not subject to any Cross-Origin-Embedder-Policy restrictions.
/// - require-corp: The document is subject to Cross-Origin-Embedder-Policy restrictions.
/// - credentialless: The document is subject to Cross-Origin-Embedder-Policy restrictions, and is not allowed to request credentials (e.g. cookies, certificates, HTTP authentication) from the user.
///
/// # Examples
///
/// ```
/// use helmet_core::CrossOriginEmbedderPolicy;
///
/// let cross_origin_embedder_policy = CrossOriginEmbedderPolicy::unsafe_none();
///
/// let cross_origin_embedder_policy = CrossOriginEmbedderPolicy::require_corp();
///
/// let cross_origin_embedder_policy = CrossOriginEmbedderPolicy::credentialless();
/// ```
#[derive(Clone)]
pub enum CrossOriginEmbedderPolicy {
    UnsafeNone,
    RequireCorp,
    Credentialless,
}

impl CrossOriginEmbedderPolicy {
    pub fn unsafe_none() -> Self {
        Self::UnsafeNone
    }

    pub fn require_corp() -> Self {
        Self::RequireCorp
    }

    pub fn credentialless() -> Self {
        Self::Credentialless
    }
}

impl Display for CrossOriginEmbedderPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrossOriginEmbedderPolicy::UnsafeNone => write!(f, "unsafe-none"),
            CrossOriginEmbedderPolicy::RequireCorp => write!(f, "require-corp"),
            CrossOriginEmbedderPolicy::Credentialless => write!(f, "credentialless"),
        }
    }
}

impl Header for CrossOriginEmbedderPolicy {
    fn name(&self) -> &'static str {
        "Cross-Origin-Embedder-Policy"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `Cross-Origin-Opener-Policy` header
///
/// The Cross-Origin-Opener-Policy HTTP response header restricts how selected resources are allowed to interact with the document's browsing context in response to user navigation. Each resource can declare an opener policy which applies to the resource's corresponding browsing context.
///
/// # Values
///
/// - same-origin: The resource's browsing context is the same-origin as the document's browsing context.
/// - same-origin-allow-popups: The resource's browsing context is the same-origin as the document's browsing context, and the resource is allowed to open new browsing contexts.
/// - unsafe-none: The resource's browsing context is cross-origin with the document's browsing context.
///
/// # Examples
///
/// ```
/// use helmet_core::CrossOriginOpenerPolicy;
///
/// let cross_origin_opener_policy = CrossOriginOpenerPolicy::same_origin();
/// ```
#[derive(Clone)]
pub enum CrossOriginOpenerPolicy {
    SameOrigin,
    SameOriginAllowPopups,
    UnsafeNone,
}

impl CrossOriginOpenerPolicy {
    pub fn same_origin() -> Self {
        Self::SameOrigin
    }

    pub fn same_origin_allow_popups() -> Self {
        Self::SameOriginAllowPopups
    }

    pub fn unsafe_none() -> Self {
        Self::UnsafeNone
    }
}

impl Display for CrossOriginOpenerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrossOriginOpenerPolicy::SameOrigin => write!(f, "same-origin"),
            CrossOriginOpenerPolicy::SameOriginAllowPopups => write!(f, "same-origin-allow-popups"),
            CrossOriginOpenerPolicy::UnsafeNone => write!(f, "unsafe-none"),
        }
    }
}

impl Header for CrossOriginOpenerPolicy {
    fn name(&self) -> &'static str {
        "Cross-Origin-Opener-Policy"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `Cross-Origin-Resource-Policy` header
///
/// The Cross-Origin-Resource-Policy HTTP response header conveys a desire that the browser blocks no-cors cross-origin/cross-site requests to the given resource.
///
/// # Values
///
/// - same-origin: The resource is same-origin to the document.
/// - same-site: The resource is same-site to the document.
/// - cross-origin: The resource is cross-origin to the document.
///
/// # Examples
///
/// ```
/// use helmet_core::CrossOriginResourcePolicy;
///
/// let cross_origin_resource_policy = CrossOriginResourcePolicy::same_origin();
/// ```
#[derive(Clone)]
pub enum CrossOriginResourcePolicy {
    SameOrigin,
    SameSite,
    CrossOrigin,
}

impl CrossOriginResourcePolicy {
    pub fn same_origin() -> Self {
        Self::SameOrigin
    }

    pub fn same_site() -> Self {
        Self::SameSite
    }

    pub fn cross_origin() -> Self {
        Self::CrossOrigin
    }
}

impl Display for CrossOriginResourcePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrossOriginResourcePolicy::SameOrigin => write!(f, "same-origin"),
            CrossOriginResourcePolicy::SameSite => write!(f, "same-site"),
            CrossOriginResourcePolicy::CrossOrigin => write!(f, "cross-origin"),
        }
    }
}

impl Header for CrossOriginResourcePolicy {
    fn name(&self) -> &'static str {
        "Cross-Origin-Resource-Policy"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `Origin-Agent-Cluster` header
///
/// The Origin-Agent-Cluster HTTP request header indicates that the client prefers an "origin agent cluster" (OAC) for the origin of the resource being requested. An OAC is a cluster of servers that are controlled by the same entity as the origin server, and that are geographically close to the client. The OAC is used to provide the client with a better experience, for example by serving content from a server that is close to the client, or by serving content that is optimized for the client's device.
///
/// # Values
///
/// - 0: The client does not prefer an OAC.
/// - 1: The client prefers an OAC.
///
/// # Examples
///
/// ```
/// use helmet_core::OriginAgentCluster;
///
/// let origin_agent_cluster = OriginAgentCluster::new(true);
/// ```
#[derive(Clone)]
pub struct OriginAgentCluster(bool);

impl OriginAgentCluster {
    pub fn new(prefer_mobile_experience: bool) -> Self {
        Self(prefer_mobile_experience)
    }
}

impl Display for OriginAgentCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 {
            write!(f, "?1")
        } else {
            write!(f, "?0")
        }
    }
}

impl Header for OriginAgentCluster {
    fn name(&self) -> &'static str {
        "Origin-Agent-Cluster"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `Referrer-Policy` header
///
/// The Referrer-Policy HTTP response header controls how much referrer information (sent via the Referer header) should be included with requests.
///
/// # Values
///
/// - no-referrer: The Referer header will be omitted entirely. No referrer information is sent along with requests.
/// - no-referrer-when-downgrade: The Referer header will be omitted entirely. However, if the protected resource URL scheme is HTTPS, then the full path will still be sent as a referrer.
/// - origin: Only send the origin of the document as the referrer in all cases. The document https://example.com/page.html will send the referrer https://example.com/.
/// - origin-when-cross-origin: Send a full URL when performing a same-origin request, but only send the origin of the document for other cases.
/// - same-origin: A referrer will be sent for same-site origins, but cross-origin requests will contain no referrer information.
/// - strict-origin: Only send the origin of the document as the referrer when the protocol security level stays the same (HTTPS→HTTPS), but don't send it to a less secure destination (HTTPS→HTTP).
/// - strict-origin-when-cross-origin: Send a full URL when performing a same-origin request, only send the origin when the protocol security level stays the same (HTTPS→HTTPS), and send no header to a less secure destination (HTTPS→HTTP).
/// - unsafe-url: Send a full URL (stripped from parameters) when performing a same-origin or cross-origin request. This policy will leak origins and paths from TLS-protected resources to insecure origins. Carefully consider the impact of this setting.
///
/// # Examples
///
/// ```
/// use helmet_core::ReferrerPolicy;
///
/// let referrer_policy = ReferrerPolicy::no_referrer();
/// ```
#[derive(Clone)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

impl ReferrerPolicy {
    pub fn no_referrer() -> Self {
        Self::NoReferrer
    }

    pub fn no_referrer_when_downgrade() -> Self {
        Self::NoReferrerWhenDowngrade
    }

    pub fn origin() -> Self {
        Self::Origin
    }

    pub fn origin_when_cross_origin() -> Self {
        Self::OriginWhenCrossOrigin
    }

    pub fn same_origin() -> Self {
        Self::SameOrigin
    }

    pub fn strict_origin() -> Self {
        Self::StrictOrigin
    }

    pub fn strict_origin_when_cross_origin() -> Self {
        Self::StrictOriginWhenCrossOrigin
    }

    pub fn unsafe_url() -> Self {
        Self::UnsafeUrl
    }
}

impl Display for ReferrerPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReferrerPolicy::NoReferrer => write!(f, "no-referrer"),
            ReferrerPolicy::NoReferrerWhenDowngrade => write!(f, "no-referrer-when-downgrade"),
            ReferrerPolicy::Origin => write!(f, "origin"),
            ReferrerPolicy::OriginWhenCrossOrigin => write!(f, "origin-when-cross-origin"),
            ReferrerPolicy::SameOrigin => write!(f, "same-origin"),
            ReferrerPolicy::StrictOrigin => write!(f, "strict-origin"),
            ReferrerPolicy::StrictOriginWhenCrossOrigin => {
                write!(f, "strict-origin-when-cross-origin")
            }
            ReferrerPolicy::UnsafeUrl => write!(f, "unsafe-url"),
        }
    }
}

impl Header for ReferrerPolicy {
    fn name(&self) -> &'static str {
        "Referrer-Policy"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `Strict-Transport-Security` header
///
/// The Strict-Transport-Security HTTP response header (often abbreviated as HSTS) lets a web site tell browsers that it should only be accessed using HTTPS, instead of using HTTP.
///
/// # Values
///
/// - max-age: The time, in seconds, that the browser should remember that a site is only to be accessed using HTTPS.
/// - includeSubDomains: If this optional parameter is specified, this rule applies to all of the site's subdomains as well.
/// - preload: If this optional parameter is specified, this rule applies to all of the site's subdomains as well.
///
/// # Examples
///
/// ```
/// use helmet_core::StrictTransportSecurity;
///
/// let strict_transport_security = StrictTransportSecurity::default();
///
/// let custom_strict_transport_security = StrictTransportSecurity::default()
///    .max_age(31536000)
///    .include_sub_domains()
///    .preload();
/// ```
#[derive(Clone)]
pub struct StrictTransportSecurity {
    max_age: u32,
    include_sub_domains: bool,
    preload: bool,
}

impl StrictTransportSecurity {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn max_age(mut self, max_age: u32) -> Self {
        self.max_age = max_age;
        self
    }

    pub fn include_sub_domains(mut self) -> Self {
        self.include_sub_domains = true;
        self
    }

    pub fn preload(mut self) -> Self {
        self.preload = true;
        self
    }
}

impl Default for StrictTransportSecurity {
    fn default() -> Self {
        Self {
            max_age: 31536000,
            include_sub_domains: false,
            preload: false,
        }
    }
}

impl Display for StrictTransportSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "max-age={}", self.max_age)?;
        if self.include_sub_domains {
            write!(f, "; includeSubDomains")?;
        }
        if self.preload {
            write!(f, "; preload")?;
        }
        Ok(())
    }
}

impl Header for StrictTransportSecurity {
    fn name(&self) -> &'static str {
        "Strict-Transport-Security"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `X-Content-Type-Options` header
///
/// The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in the Content-Type headers should not be changed and be followed. This allows to opt-out of MIME type sniffing, or, in other words, it is a way to say that the webmasters knew what they were doing.
///
/// # Values
///
/// - nosniff: Prevents the browser from MIME-sniffing a response away from the declared content-type. This also applies to Google Chrome, when downloading extensions.
///
/// # Examples
///
/// ```
/// use helmet_core::XContentTypeOptions;
///
/// let x_content_type_options = XContentTypeOptions::nosniff();
/// ```
#[derive(Clone)]
pub enum XContentTypeOptions {
    NoSniff,
}

impl XContentTypeOptions {
    pub fn nosniff() -> Self {
        Self::NoSniff
    }
}

impl Display for XContentTypeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XContentTypeOptions::NoSniff => write!(f, "nosniff"),
        }
    }
}

impl Header for XContentTypeOptions {
    fn name(&self) -> &'static str {
        "X-Content-Type-Options"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `X-DNS-Prefetch-Control` header
///
/// The X-DNS-Prefetch-Control HTTP response header controls DNS prefetching, a feature by which browsers proactively perform domain name resolution on both links that the user may choose to follow as well as URLs for items referenced by the document, including images, CSS, JavaScript, and so forth.
///
/// # Values
///
/// - off: Disable DNS prefetching.
/// - on: Enable DNS prefetching, allowing the browser to proactively perform domain name resolution on both links that the user may choose to follow as well as URLs for items referenced by the document, including images, CSS, JavaScript, and so forth.
///
/// # Examples
///
/// ```
/// use helmet_core::XDNSPrefetchControl;
///
/// let x_dns_prefetch_control = XDNSPrefetchControl::off();
/// ```
#[derive(Clone)]
pub enum XDNSPrefetchControl {
    Off,
    On,
}

impl XDNSPrefetchControl {
    pub fn off() -> Self {
        Self::Off
    }

    pub fn on() -> Self {
        Self::On
    }
}

impl Display for XDNSPrefetchControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XDNSPrefetchControl::Off => write!(f, "off"),
            XDNSPrefetchControl::On => write!(f, "on"),
        }
    }
}

impl Header for XDNSPrefetchControl {
    fn name(&self) -> &'static str {
        "X-DNS-Prefetch-Control"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `X-Download-Options` header
///
/// The X-Download-Options HTTP response header indicates that the browser (Internet Explorer) should not display the option to "Open" a file that has been downloaded from an application, to prevent phishing attacks that could trick users into opening potentially malicious content that could infect their computer.
///
/// # Values
///
/// - noopen: Prevents Internet Explorer from executing downloads in your site’s context.
///
/// # Examples
///
/// ```
/// use helmet_core::XDownloadOptions;
///
/// let x_download_options = XDownloadOptions::noopen();
/// ```
#[derive(Clone)]
pub enum XDownloadOptions {
    NoOpen,
}

impl XDownloadOptions {
    pub fn noopen() -> Self {
        Self::NoOpen
    }
}

impl Display for XDownloadOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XDownloadOptions::NoOpen => write!(f, "noopen"),
        }
    }
}

impl Header for XDownloadOptions {
    fn name(&self) -> &'static str {
        "X-Download-Options"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `X-Frame-Options` header
///
/// The X-Frame-Options HTTP response header can be used to to avoid click-jacking attacks by preventing the content to be included in other websites.
///
/// # Values
///
/// - deny: The page cannot be displayed in a frame, regardless of the site attempting to do so.
/// - sameorigin: The page can only be displayed in a frame on the same origin as the page itself.
/// - allow-from: The page can only be displayed in a frame on the specified origin. Requires a URI as an argument.
///
/// # Examples
///
/// ```
/// use helmet_core::XFrameOptions;
///
/// let x_frame_options = XFrameOptions::deny();
///
/// let x_frame_options = XFrameOptions::same_origin();
///
/// let x_frame_options = XFrameOptions::allow_from("https://example.com");
/// ```
#[derive(Clone)]
pub enum XFrameOptions {
    Deny,
    SameOrigin,
    // deprecated - use Content-Security-Policy instead see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options#allow-from_origin
    AllowFrom(String),
}

impl XFrameOptions {
    pub fn deny() -> Self {
        Self::Deny
    }

    pub fn same_origin() -> Self {
        Self::SameOrigin
    }

    pub fn allow_from(uri: &str) -> Self {
        Self::AllowFrom(uri.to_string())
    }
}

impl Display for XFrameOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XFrameOptions::Deny => write!(f, "DENY"),
            XFrameOptions::SameOrigin => write!(f, "SAMEORIGIN"),
            XFrameOptions::AllowFrom(uri) => write!(f, "ALLOW-FROM {}", uri),
        }
    }
}

impl Header for XFrameOptions {
    fn name(&self) -> &'static str {
        "X-Frame-Options"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `X-Permitted-Cross-Domain-Policies` header
///
/// The X-Permitted-Cross-Domain-Policies HTTP response header determines whether cross-domain policy files (crossdomain.xml and clientaccesspolicy.xml) will be ignored by Flash and Adobe Acrobat in subsequent requests.
///
/// # Values
///
/// - none: No policy file is allowed.
/// - master-only: Only a master policy file, but no other policy files, is allowed.
/// - by-content-type: A policy file is allowed if its MIME type matches the Content-Type of the requested resource.
/// - by-ftp-filename: A policy file is allowed if its URL matches the URL of the requested resource.
/// - all: Any policy file is allowed.
///
/// # Examples
///
/// ```
/// use helmet_core::XPermittedCrossDomainPolicies;
///
/// let x_permitted_cross_domain_policies = XPermittedCrossDomainPolicies::none();
///
/// let x_permitted_cross_domain_policies = XPermittedCrossDomainPolicies::master_only();
///
/// let x_permitted_cross_domain_policies = XPermittedCrossDomainPolicies::by_content_type();
///
/// let x_permitted_cross_domain_policies = XPermittedCrossDomainPolicies::by_ftp_filename();
///
/// let x_permitted_cross_domain_policies = XPermittedCrossDomainPolicies::all();
/// ```
#[derive(Clone)]
pub enum XPermittedCrossDomainPolicies {
    None,
    MasterOnly,
    ByContentType,
    ByFtpFilename,
    All,
}

impl XPermittedCrossDomainPolicies {
    pub fn none() -> Self {
        Self::None
    }

    pub fn master_only() -> Self {
        Self::MasterOnly
    }

    pub fn by_content_type() -> Self {
        Self::ByContentType
    }

    pub fn by_ftp_filename() -> Self {
        Self::ByFtpFilename
    }

    pub fn all() -> Self {
        Self::All
    }
}

impl Display for XPermittedCrossDomainPolicies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XPermittedCrossDomainPolicies::None => write!(f, "none"),
            XPermittedCrossDomainPolicies::MasterOnly => write!(f, "master-only"),
            XPermittedCrossDomainPolicies::ByContentType => write!(f, "by-content-type"),
            XPermittedCrossDomainPolicies::ByFtpFilename => write!(f, "by-ftp-filename"),
            XPermittedCrossDomainPolicies::All => write!(f, "all"),
        }
    }
}

impl Header for XPermittedCrossDomainPolicies {
    fn name(&self) -> &'static str {
        "X-Permitted-Cross-Domain-Policies"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `X-XSS-Protection` header
///
/// The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks. Although these protections are largely unnecessary in modern browsers when sites implement a strong Content-Security-Policy that disables the use of inline JavaScript ('unsafe-inline'), they can still provide protections for users of older web browsers that don't yet support CSP.
///
/// # Values
///
/// - 0: Disables XSS filtering.
/// - 1: Enables XSS filtering (usually default in browsers).
/// - 1; mode=block: Enables XSS filtering. Rather than sanitizing the page, the browser will prevent rendering of the page if an attack is detected.
/// - 1; report=<reporting-URI>: Enables XSS filtering. If a cross-site scripting attack is detected, the browser will sanitize the page and report the violation. This uses the functionality of the CSP report-uri directive to send a report.
///
/// # Examples
///
/// ```
/// use helmet_core::XXSSProtection;
///
/// let x_xss_protection = XXSSProtection::on();
///
/// let x_xss_protection = XXSSProtection::off();
///
/// let x_xss_protection = XXSSProtection::on().mode_block();
///
/// let x_xss_protection = XXSSProtection::on().report("https://example.com");
///
/// let x_xss_protection = XXSSProtection::on().mode_block().report("https://example.com");
/// ```
#[derive(Clone)]
pub struct XXSSProtection {
    on: bool,
    mode_block: bool,
    report: Option<String>,
}

impl XXSSProtection {
    /// Disables XSS filtering.
    pub fn off() -> Self {
        Self {
            on: false,
            mode_block: false,
            report: None,
        }
    }

    /// Enables XSS filtering (usually default in browsers).
    pub fn on() -> Self {
        Self {
            on: true,
            mode_block: false,
            report: None,
        }
    }

    /// Enables XSS filtering. Rather than sanitizing the page, the browser will prevent rendering of the page if an attack is detected.
    pub fn mode_block(mut self) -> Self {
        self.mode_block = true;
        self
    }

    /// Enables XSS filtering. If a cross-site scripting attack is detected, the browser will sanitize the page and report the violation. This uses the functionality of the CSP report-uri directive to send a report.
    pub fn report(mut self, report: &str) -> Self {
        self.report = Some(report.to_string());
        self
    }
}

impl Display for XXSSProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.on {
            write!(f, "1")?;
            if self.mode_block {
                write!(f, "; mode=block")?;
            }
            if let Some(report) = &self.report {
                write!(f, "; report={}", report)?;
            }
        } else {
            write!(f, "0")?;
        }
        Ok(())
    }
}

impl Header for XXSSProtection {
    fn name(&self) -> &'static str {
        "X-XSS-Protection"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `X-Powered-By` header
///
/// ntex does not set `X-Powered-By` header by default.
/// Instead of silencing the header, Helmet allows you to set it to a custom value.
/// This can be useful against primitive fingerprinting.
///
/// # Examples
///
/// ```
/// use helmet_core::XPoweredBy;
///
/// let x_powered_by = XPoweredBy::new("PHP 4.2.0");
/// ```
#[derive(Clone)]
pub struct XPoweredBy(String);

impl XPoweredBy {
    /// Set the `X-Powered-By` header to a custom value.
    pub fn new(comment: &str) -> Self {
        Self(comment.to_string())
    }
}

impl Display for XPoweredBy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        Ok(())
    }
}

impl Header for XPoweredBy {
    fn name(&self) -> &'static str {
        "X-Powered-By"
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Manages `Content-Security-Policy` header
///
/// The HTTP Content-Security-Policy response header allows web site administrators to control resources the user agent is allowed to load for a given page. With a few exceptions, policies mostly involve specifying server origins and script endpoints. This helps guard against cross-site scripting attacks (XSS).
///
/// # Directives
///
/// - child-src: Defines valid sources for web workers and nested browsing contexts loaded using elements such as `<frame>` and `<iframe>`.
/// - connect-src: Applies to XMLHttpRequest (AJAX), WebSocket or EventSource. If not allowed the browser emulates a 400 HTTP status code.
/// - default-src: The default-src is the default policy for loading content such as JavaScript, Images, CSS, Font's, AJAX requests, Frames, HTML5 Media. See the list of directives to see which values are allowed as default.
/// - font-src: Defines valid sources for fonts loaded using @font-face.
/// - frame-src: Defines valid sources for nested browsing contexts loading using elements such as `<frame>` and `<iframe>`.
/// - img-src: Defines valid sources of images and favicons.
/// - manifest-src: Specifies which manifest can be applied to the resource.
/// - media-src: Defines valid sources for loading media using the `<audio>` and `<video>` elements.
/// - object-src: Defines valid sources for the `<object>`, `<embed>`, and `<applet>` elements.
/// - prefetch-src: Specifies which referrer to use when fetching the resource.
/// - script-src: Defines valid sources for JavaScript.
/// - script-src-elem: Defines valid sources for JavaScript inline event handlers.
/// - script-src-attr: Defines valid sources for JavaScript inline event handlers.
/// - style-src: Defines valid sources for stylesheets.
/// - style-src-elem: Defines valid sources for stylesheets inline event handlers.
/// - style-src-attr: Defines valid sources for stylesheets inline event handlers.
/// - worker-src: Defines valid sources for Worker, SharedWorker, or ServiceWorker scripts.
/// - base-uri: Restricts the URLs which can be used in a document's `<base>` element.
/// - sandbox: Enables a sandbox for the requested resource similar to the iframe sandbox attribute. The sandbox applies a same origin policy, prevents popups, plugins and script execution is blocked. You can keep the sandbox value empty to keep all restrictions in place, or add values: allow-forms allow-same-origin allow-scripts allow-popups, allow-modals, allow-orientation-lock, allow-pointer-lock, allow-presentation, allow-popups-to-escape-sandbox, allow-top-navigation, allow-top-navigation-by-user-activation.
/// - form-action: Restricts the URLs which can be used as the target of a form submissions from a given context.
/// - frame-ancestors: Specifies valid parents that may embed a page using `<frame>`, `<iframe>`, `<object>`, `<embed>`, or `<applet>`.
/// - report-to: Enables reporting of violations.
/// - require-trusted-types-for: Specifies which trusted types are required by a resource.
/// - trusted-types: Specifies which trusted types are defined by a resource.
/// - upgrade-insecure-requests: Block HTTP requests on insecure elements.
///
/// # Examples
///
/// ```
/// use helmet_core::ContentSecurityPolicy;
///
/// let content_security_policy = ContentSecurityPolicy::default()
///    .child_src(vec!["'self'", "https://youtube.com"])
///    .connect_src(vec!["'self'", "https://youtube.com"])
///    .default_src(vec!["'self'", "https://youtube.com"])
///    .font_src(vec!["'self'", "https://youtube.com"]);
/// ```
#[derive(Clone)]
pub enum ContentSecurityPolicyDirective<'a> {
    /// Warning: Instead of child-src, if you want to regulate nested browsing contexts and workers, you should use the frame-src and worker-src directives, respectively.
    ChildSrc(Vec<&'a str>),
    /// Applies to XMLHttpRequest (AJAX), WebSocket or EventSource. If not allowed the browser emulates a 400 HTTP status code.
    ConnectSrc(Vec<&'a str>),
    /// The default-src is the default policy for loading content such as JavaScript, Images, CSS, Font's, AJAX requests, Frames, HTML5 Media. See the list of directives to see which values are allowed as default.
    DefaultSrc(Vec<&'a str>),
    /// Defines valid sources for fonts loaded using @font-face.
    FontSrc(Vec<&'a str>),
    /// Defines valid sources for nested browsing contexts loading using elements such as `<frame>` and `<iframe>`.
    FrameSrc(Vec<&'a str>),
    /// Defines valid sources of images and favicons.
    ImgSrc(Vec<&'a str>),
    /// Specifies which manifest can be applied to the resource.
    ManifestSrc(Vec<&'a str>),
    /// Defines valid sources for loading media using the `<audio>` and `<video>` elements.
    MediaSrc(Vec<&'a str>),
    /// Defines valid sources for the `<object>`, `<embed>`, and `<applet>` elements.
    ObjectSrc(Vec<&'a str>),
    /// Specifies which referrer to use when fetching the resource.
    PrefetchSrc(Vec<&'a str>),
    /// Defines valid sources for JavaScript.
    ScriptSrc(Vec<&'a str>),
    /// Defines valid sources for JavaScript inline event handlers.
    ScriptSrcElem(Vec<&'a str>),
    /// Defines valid sources for JavaScript inline event handlers.
    ScriptSrcAttr(Vec<&'a str>),
    /// Defines valid sources for stylesheets.
    StyleSrc(Vec<&'a str>),
    /// Defines valid sources for stylesheets inline event handlers.
    StyleSrcElem(Vec<&'a str>),
    /// Defines valid sources for stylesheets inline event handlers.
    StyleSrcAttr(Vec<&'a str>),
    /// Defines valid sources for Worker, SharedWorker, or ServiceWorker scripts.
    WorkerSrc(Vec<&'a str>),
    // Document directives
    /// Restricts the URLs which can be used in a document's `<base>` element.
    BaseUri(Vec<&'a str>),
    /// Enables a sandbox for the requested resource similar to the iframe sandbox attribute. The sandbox applies a same origin policy, prevents popups, plugins and script execution is blocked. You can keep the sandbox value empty to keep all restrictions in place, or add values: allow-forms allow-same-origin allow-scripts allow-popups, allow-modals, allow-orientation-lock, allow-pointer-lock, allow-presentation, allow-popups-to-escape-sandbox, allow-top-navigation, allow-top-navigation-by-user-activation.
    Sandbox(Vec<&'a str>),
    // Navigation directives
    /// Restricts the URLs which can be used as the target of a form submissions from a given context.
    FormAction(Vec<&'a str>),
    /// Specifies valid parents that may embed a page using `<frame>`, `<iframe>`, `<object>`, `<embed>`, or `<applet>`.
    FrameAncestors(Vec<&'a str>),
    // Reporting directives
    /// Enables reporting of violations.
    ///
    /// report-uri is deprecated, however, it is still supported by browsers that don't yet support report-to. ReportTo will apply both to report-uri and report-to with the same values, to support browsers that support both.
    ReportTo(Vec<&'a str>),
    // Other
    /// Specifies which trusted types are required by a resource.
    RequireTrustedTypesFor(Vec<&'a str>),
    /// Specifies which trusted types are defined by a resource.
    TrustedTypes(Vec<&'a str>),
    /// Block HTTP requests on insecure elements.
    UpgradeInsecureRequests,
}

impl<'a> ContentSecurityPolicyDirective<'a> {
    /// child-src: Defines valid sources for web workers and nested browsing contexts loaded using elements such as `<frame>`` and `<iframe>`.
    pub fn child_src(values: Vec<&'a str>) -> Self {
        Self::ChildSrc(values)
    }

    /// connect-src: Applies to XMLHttpRequest (AJAX), WebSocket or EventSource. If not allowed the browser emulates a 400 HTTP status code.
    pub fn connect_src(values: Vec<&'a str>) -> Self {
        Self::ConnectSrc(values)
    }

    /// default-src: The default-src is the default policy for loading content such as JavaScript, Images, CSS, Font's, AJAX requests, Frames, HTML5 Media. See the list of directives to see which values are allowed as default.
    pub fn default_src(values: Vec<&'a str>) -> Self {
        Self::DefaultSrc(values)
    }

    /// font-src: Defines valid sources for fonts loaded using @font-face.
    pub fn font_src(values: Vec<&'a str>) -> Self {
        Self::FontSrc(values)
    }

    /// frame-src: Defines valid sources for nested browsing contexts loading using elements such as `<frame>` and `<iframe>`.
    pub fn frame_src(values: Vec<&'a str>) -> Self {
        Self::FrameSrc(values)
    }

    /// img-src: Defines valid sources of images and favicons.
    pub fn img_src(values: Vec<&'a str>) -> Self {
        Self::ImgSrc(values)
    }

    /// manifest-src: Specifies which manifest can be applied to the resource.
    pub fn manifest_src(values: Vec<&'a str>) -> Self {
        Self::ManifestSrc(values)
    }

    /// media-src: Defines valid sources for loading media using the `<audio>` and `<video>` elements.
    pub fn media_src(values: Vec<&'a str>) -> Self {
        Self::MediaSrc(values)
    }

    /// object-src: Defines valid sources for the `<object>`, `<embed>`, and `<applet>` elements.
    pub fn object_src(values: Vec<&'a str>) -> Self {
        Self::ObjectSrc(values)
    }

    /// prefetch-src: Specifies which referrer to use when fetching the resource.
    pub fn prefetch_src(values: Vec<&'a str>) -> Self {
        Self::PrefetchSrc(values)
    }

    /// script-src: Defines valid sources for JavaScript.
    pub fn script_src(values: Vec<&'a str>) -> Self {
        Self::ScriptSrc(values)
    }

    /// script-src-elem: Defines valid sources for JavaScript inline event handlers.
    pub fn script_src_elem(values: Vec<&'a str>) -> Self {
        Self::ScriptSrcElem(values)
    }

    /// script-src-attr: Defines valid sources for JavaScript inline event handlers.
    pub fn script_src_attr(values: Vec<&'a str>) -> Self {
        Self::ScriptSrcAttr(values)
    }

    /// style-src: Defines valid sources for stylesheets.
    pub fn style_src(values: Vec<&'a str>) -> Self {
        Self::StyleSrc(values)
    }

    /// style-src-elem: Defines valid sources for stylesheets inline event handlers.
    pub fn style_src_elem(values: Vec<&'a str>) -> Self {
        Self::StyleSrcElem(values)
    }

    /// style-src-attr: Defines valid sources for stylesheets inline event handlers.
    pub fn style_src_attr(values: Vec<&'a str>) -> Self {
        Self::StyleSrcAttr(values)
    }

    /// worker-src: Defines valid sources for Worker, SharedWorker, or ServiceWorker scripts.
    pub fn worker_src(values: Vec<&'a str>) -> Self {
        Self::WorkerSrc(values)
    }

    /// base-uri: Restricts the URLs which can be used in a document's `<base>` element.
    pub fn base_uri(values: Vec<&'a str>) -> Self {
        Self::BaseUri(values)
    }

    /// sandbox: Enables a sandbox for the requested resource similar to the iframe sandbox attribute. The sandbox applies a same origin policy, prevents popups, plugins and script execution is blocked. You can keep the sandbox value empty to keep all restrictions in place, or add values: allow-forms allow-same-origin allow-scripts allow-popups, allow-modals, allow-orientation-lock, allow-pointer-lock, allow-presentation, allow-popups-to-escape-sandbox, allow-top-navigation, allow-top-navigation-by-user-activation.
    pub fn sandbox(values: Vec<&'a str>) -> Self {
        Self::Sandbox(values)
    }

    /// form-action: Restricts the URLs which can be used as the target of a form submissions from a given context.
    pub fn form_action(values: Vec<&'a str>) -> Self {
        Self::FormAction(values)
    }

    /// frame-ancestors: Specifies valid parents that may embed a page using `<frame>`, `<iframe>`, `<object>`, `<embed>`, or `<applet>`.
    pub fn frame_ancestors(values: Vec<&'a str>) -> Self {
        Self::FrameAncestors(values)
    }

    /// report-to: Enables reporting of violations.
    pub fn report_to(values: Vec<&'a str>) -> Self {
        Self::ReportTo(values)
    }

    /// require-trusted-types-for: Specifies which trusted types are required by a resource.
    pub fn require_trusted_types_for(values: Vec<&'a str>) -> Self {
        Self::RequireTrustedTypesFor(values)
    }

    /// trusted-types: Specifies which trusted types are defined by a resource.
    pub fn trusted_types(values: Vec<&'a str>) -> Self {
        Self::TrustedTypes(values)
    }

    /// Block HTTP requests on insecure elements.
    pub fn upgrade_insecure_requests() -> Self {
        Self::UpgradeInsecureRequests
    }
}

impl Display for ContentSecurityPolicyDirective<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentSecurityPolicyDirective::ChildSrc(values) => {
                write!(f, "child-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::ConnectSrc(values) => {
                write!(f, "connect-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::DefaultSrc(values) => {
                write!(f, "default-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::FontSrc(values) => {
                write!(f, "font-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::FrameSrc(values) => {
                write!(f, "frame-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::ImgSrc(values) => {
                write!(f, "img-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::ManifestSrc(values) => {
                write!(f, "manifest-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::MediaSrc(values) => {
                write!(f, "media-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::ObjectSrc(values) => {
                write!(f, "object-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::PrefetchSrc(values) => {
                write!(f, "prefetch-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::ScriptSrc(values) => {
                write!(f, "script-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::ScriptSrcElem(values) => {
                write!(f, "script-src-elem {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::ScriptSrcAttr(values) => {
                write!(f, "script-src-attr {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::StyleSrc(values) => {
                write!(f, "style-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::StyleSrcElem(values) => {
                write!(f, "style-src-elem {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::StyleSrcAttr(values) => {
                write!(f, "style-src-attr {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::WorkerSrc(values) => {
                write!(f, "worker-src {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::BaseUri(values) => {
                write!(f, "base-uri {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::Sandbox(values) => {
                write!(f, "sandbox {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::FormAction(values) => {
                write!(f, "form-action {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::FrameAncestors(values) => {
                write!(f, "frame-ancestors {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::ReportTo(values) => {
                let values = values.join(" ");
                write!(f, "report-to {}; report-uri {}", values, values)
            }
            ContentSecurityPolicyDirective::RequireTrustedTypesFor(values) => {
                write!(f, "require-trusted-types-for {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::TrustedTypes(values) => {
                write!(f, "trusted-types {}", values.join(" "))
            }
            ContentSecurityPolicyDirective::UpgradeInsecureRequests => {
                write!(f, "upgrade-insecure-requests")
            }
        }
    }
}

/// Manages `Content-Security-Policy` header
///
/// The HTTP Content-Security-Policy response header allows web site administrators to control resources the user agent is allowed to load for a given page. With a few exceptions, policies mostly involve specifying server origins and script endpoints. This helps guard against cross-site scripting attacks (XSS).
///
/// # Examples
///
/// ```
/// use helmet_core::ContentSecurityPolicy;
///
/// let content_security_policy = ContentSecurityPolicy::default()
///    .child_src(vec!["'self'", "https://youtube.com"])
///    .connect_src(vec!["'self'", "https://youtube.com"])
///    .default_src(vec!["'self'", "https://youtube.com"])
///    .font_src(vec!["'self'", "https://youtube.com"]);
/// ```
///
/// ## Report only
///
/// In report only mode, the browser will not block the request, but will send a report to the specified URI.
///
/// Make sure to set the `report-to` directive.
///
/// ```
/// use helmet_core::ContentSecurityPolicy;
///
/// let content_security_policy = ContentSecurityPolicy::default()
///    .child_src(vec!["'self'", "https://youtube.com"])
///    .report_to(vec!["https://example.com/report"])
///    .report_only();
/// ```
#[derive(Clone)]
pub struct ContentSecurityPolicy<'a> {
    directives: Vec<ContentSecurityPolicyDirective<'a>>,
    report_only: bool,
}

impl<'a> ContentSecurityPolicy<'a> {
    pub fn new() -> Self {
        Self {
            directives: Vec::new(),
            report_only: false,
        }
    }

    fn directive(mut self, directive: ContentSecurityPolicyDirective<'a>) -> Self {
        self.directives.push(directive);
        self
    }

    /// child-src: Defines valid sources for web workers and nested browsing contexts loaded using elements such as `<frame>` and `<iframe>`.
    pub fn child_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::child_src(values))
    }

    /// connect-src: Applies to XMLHttpRequest (AJAX), WebSocket or EventSource. If not allowed the browser emulates a 400 HTTP status code.
    pub fn connect_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::connect_src(values))
    }

    /// default-src: The default-src is the default policy for loading content such as JavaScript, Images, CSS, Font's, AJAX requests, Frames, HTML5 Media. See the list of directives to see which values are allowed as default.
    pub fn default_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::default_src(values))
    }

    /// font-src: Defines valid sources for fonts loaded using @font-face.
    pub fn font_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::font_src(values))
    }

    /// frame-src: Defines valid sources for nested browsing contexts loading using elements such as `<frame>` and `<iframe>`.
    pub fn frame_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::frame_src(values))
    }

    /// img-src: Defines valid sources of images and favicons.
    pub fn img_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::img_src(values))
    }

    /// manifest-src: Specifies which manifest can be applied to the resource.
    pub fn manifest_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::manifest_src(values))
    }

    /// media-src: Defines valid sources for loading media using the `<audio>` and `<video>` elements.
    pub fn media_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::media_src(values))
    }

    /// object-src: Defines valid sources for the `<object>`, `<embed>`, and `<applet>` elements.
    pub fn object_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::object_src(values))
    }

    /// prefetch-src: Specifies which referrer to use when fetching the resource.
    pub fn prefetch_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::prefetch_src(values))
    }

    /// script-src: Defines valid sources for JavaScript.
    pub fn script_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::script_src(values))
    }

    /// script-src-elem: Defines valid sources for JavaScript inline event handlers.
    pub fn script_src_elem(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::script_src_elem(values))
    }

    /// script-src-attr: Defines valid sources for JavaScript inline event handlers.
    pub fn script_src_attr(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::script_src_attr(values))
    }

    /// style-src: Defines valid sources for stylesheets.
    pub fn style_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::style_src(values))
    }

    /// style-src-elem: Defines valid sources for stylesheets inline event handlers.
    pub fn style_src_elem(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::style_src_elem(values))
    }

    /// style-src-attr: Defines valid sources for stylesheets inline event handlers.
    pub fn style_src_attr(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::style_src_attr(values))
    }

    /// worker-src: Defines valid sources for Worker, SharedWorker, or ServiceWorker scripts.
    pub fn worker_src(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::worker_src(values))
    }

    /// base-uri: Restricts the URLs which can be used in a document's `<base>` element.
    pub fn base_uri(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::base_uri(values))
    }

    /// sandbox: Enables a sandbox for the requested resource similar to the iframe sandbox attribute. The sandbox applies a same origin policy, prevents popups, plugins and script execution is blocked. You can keep the sandbox value empty to keep all restrictions in place, or add values: allow-forms allow-same-origin allow-scripts allow-popups, allow-modals, allow-orientation-lock, allow-pointer-lock, allow-presentation, allow-popups-to-escape-sandbox, allow-top-navigation, allow-top-navigation-by-user-activation.
    pub fn sandbox(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::sandbox(values))
    }

    /// form-action: Restricts the URLs which can be used as the target of a form submissions from a given context.
    pub fn form_action(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::form_action(values))
    }

    /// frame-ancestors: Specifies valid parents that may embed a page using `<frame>`, `<iframe>`, `<object>`, `<embed>`, or `<applet>`.
    pub fn frame_ancestors(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::frame_ancestors(values))
    }

    /// report-to: Enables reporting of violations.
    pub fn report_to(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::report_to(values))
    }

    /// require-trusted-types-for: Specifies which trusted types are required by a resource.
    pub fn require_trusted_types_for(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::require_trusted_types_for(
            values,
        ))
    }

    /// trusted-types: Specifies which trusted types are defined by a resource.
    pub fn trusted_types(self, values: Vec<&'a str>) -> Self {
        self.directive(ContentSecurityPolicyDirective::trusted_types(values))
    }

    /// Block HTTP requests on insecure elements.
    pub fn upgrade_insecure_requests(self) -> Self {
        self.directive(ContentSecurityPolicyDirective::upgrade_insecure_requests())
    }

    /// Enable report only mode
    ///
    /// When set to true, the `Content-Security-Policy-Report-Only` header is set instead of `Content-Security-Policy`.
    ///
    /// Defaults to false.
    ///
    /// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
    pub fn report_only(mut self) -> Self {
        self.report_only = true;
        self
    }
}

impl<'a> Display for ContentSecurityPolicy<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let directives = self
            .directives
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<String>>()
            .join("; ");
        write!(f, "{}", directives)
    }
}

impl<'a> Default for ContentSecurityPolicy<'a> {
    /// Default policy for the Content-Security-Policy header.
    ///
    /// values:
    /// ```text
    /// default-src 'self';
    /// base-uri 'self';
    /// font-src 'self' https: data:;
    /// form-action 'self';
    /// frame-ancestors 'self';
    /// img-src 'self' data:;
    /// object-src 'none';
    /// script-src 'self';
    /// script-src-attr 'none';
    /// style-src 'self' https: 'unsafe-inline';
    /// upgrade-insecure-requests
    /// ```
    fn default() -> Self {
        Self::new()
            .default_src(vec!["'self'"])
            .base_uri(vec!["'self'"])
            .font_src(vec!["'self'", "https:", "data:"])
            .form_action(vec!["'self'"])
            .frame_ancestors(vec!["'self'"])
            .img_src(vec!["'self'", "data:"])
            .object_src(vec!["'none'"])
            .script_src(vec!["'self'"])
            .script_src_attr(vec!["'none'"])
            .style_src(vec!["'self'", "https:", "'unsafe-inline'"])
            .upgrade_insecure_requests()
    }
}

impl<'a> Header for ContentSecurityPolicy<'a> {
    fn name(&self) -> &'static str {
        if self.report_only {
            "Content-Security-Policy-Report-Only"
        } else {
            "Content-Security-Policy"
        }
    }

    fn value(&self) -> String {
        self.to_string()
    }
}

/// Helmet security headers middleware for ntex services
///
/// # Examples
///
/// ```
/// use helmet_core::Helmet;
///
/// let helmet = Helmet::default();
/// ```
///
/// ## Adding custom headers
///
/// ```
/// use helmet_core::{Helmet, StrictTransportSecurity};
///
/// let helmet = Helmet::new()
///    .add(StrictTransportSecurity::new().max_age(31536000).include_sub_domains());
/// ```
pub struct Helmet {
    pub headers: Vec<Box<dyn Header>>,
}

impl Helmet {
    /// Create new `Helmet` instance without any headers applied
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
        }
    }

    /// Add header to the middleware
    pub fn add(mut self, header: impl Header + 'static) -> Self {
        self.headers.push(Box::new(header));
        self
    }
}

impl Default for Helmet {
    /// Default `Helmet` instance with all headers applied
    ///
    /// ```text
    /// Content-Security-Policy: default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests
    /// Cross-Origin-Opener-Policy: same-origin
    /// Cross-Origin-Resource-Policy: same-origin
    /// Origin-Agent-Cluster: ?1
    /// Referrer-Policy: no-referrer
    /// Strict-Transport-Security: max-age=15552000; includeSubDomains
    /// X-Content-Type-Options: nosniff
    /// X-DNS-Prefetch-Control: off
    /// X-Download-Options: noopen
    /// X-Frame-Options: sameorigin
    /// X-Permitted-Cross-Domain-Policies: none
    /// X-XSS-Protection: 0
    /// ```
    fn default() -> Self {
        Self::new()
            .add(ContentSecurityPolicy::default())
            .add(CrossOriginOpenerPolicy::same_origin())
            .add(CrossOriginResourcePolicy::same_origin())
            .add(OriginAgentCluster(true))
            .add(ReferrerPolicy::no_referrer())
            .add(
                StrictTransportSecurity::new()
                    .max_age(15552000)
                    .include_sub_domains(),
            )
            .add(XContentTypeOptions::nosniff())
            .add(XDNSPrefetchControl::off())
            .add(XDownloadOptions::noopen())
            .add(XFrameOptions::same_origin())
            .add(XPermittedCrossDomainPolicies::none())
            .add(XXSSProtection::off())
    }
}
