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
/// impl Into<Header> for MyHeader {
///     fn into(self) -> Header {
///         ("My-Header", "My-Value".to_owned())
///    }
/// }
/// ```
pub type Header = (&'static str, String);

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

impl CrossOriginEmbedderPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            CrossOriginEmbedderPolicy::UnsafeNone => "unsafe-none",
            CrossOriginEmbedderPolicy::RequireCorp => "require-corp",
            CrossOriginEmbedderPolicy::Credentialless => "credentialless",
        }
    }
}

impl From<CrossOriginEmbedderPolicy> for Header {
    fn from(val: CrossOriginEmbedderPolicy) -> Self {
        ("Cross-Origin-Embedder-Policy", val.as_str().to_owned())
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

impl CrossOriginOpenerPolicy {
    fn as_str(&self) -> &'static str {
        match self {
            CrossOriginOpenerPolicy::SameOrigin => "same-origin",
            CrossOriginOpenerPolicy::SameOriginAllowPopups => "same-origin-allow-popups",
            CrossOriginOpenerPolicy::UnsafeNone => "unsafe-none",
        }
    }
}

impl From<CrossOriginOpenerPolicy> for Header {
    fn from(val: CrossOriginOpenerPolicy) -> Self {
        ("Cross-Origin-Opener-Policy", val.as_str().to_owned())
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

impl CrossOriginResourcePolicy {
    fn as_str(&self) -> &'static str {
        match self {
            CrossOriginResourcePolicy::SameOrigin => "same-origin",
            CrossOriginResourcePolicy::SameSite => "same-site",
            CrossOriginResourcePolicy::CrossOrigin => "cross-origin",
        }
    }
}

impl From<CrossOriginResourcePolicy> for Header {
    fn from(val: CrossOriginResourcePolicy) -> Self {
        ("Cross-Origin-Resource-Policy", val.as_str().to_owned())
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

impl OriginAgentCluster {
    fn as_str(&self) -> &'static str {
        if self.0 {
            "?1"
        } else {
            "?0"
        }
    }
}

impl From<OriginAgentCluster> for Header {
    fn from(val: OriginAgentCluster) -> Self {
        ("Origin-Agent-Cluster", val.as_str().to_owned())
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

impl ReferrerPolicy {
    fn as_str(&self) -> &'static str {
        match self {
            ReferrerPolicy::NoReferrer => "no-referrer",
            ReferrerPolicy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            ReferrerPolicy::Origin => "origin",
            ReferrerPolicy::OriginWhenCrossOrigin => "origin-when-cross-origin",
            ReferrerPolicy::SameOrigin => "same-origin",
            ReferrerPolicy::StrictOrigin => "strict-origin",
            ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            ReferrerPolicy::UnsafeUrl => "unsafe-url",
        }
    }
}

impl From<ReferrerPolicy> for Header {
    fn from(val: ReferrerPolicy) -> Self {
        ("Referrer-Policy", val.as_str().to_owned())
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

impl From<StrictTransportSecurity> for Header {
    fn from(val: StrictTransportSecurity) -> Self {
        ("Strict-Transport-Security", val.to_string())
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

impl XContentTypeOptions {
    fn as_str(&self) -> &'static str {
        match self {
            XContentTypeOptions::NoSniff => "nosniff",
        }
    }
}

impl Display for XContentTypeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XContentTypeOptions::NoSniff => write!(f, "nosniff"),
        }
    }
}

impl From<XContentTypeOptions> for Header {
    fn from(val: XContentTypeOptions) -> Self {
        ("X-Content-Type-Options", val.as_str().to_owned())
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

impl XDNSPrefetchControl {
    fn as_str(&self) -> &'static str {
        match self {
            XDNSPrefetchControl::Off => "off",
            XDNSPrefetchControl::On => "on",
        }
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

impl From<XDNSPrefetchControl> for Header {
    fn from(val: XDNSPrefetchControl) -> Self {
        ("X-DNS-Prefetch-Control", val.as_str().to_owned())
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

impl XDownloadOptions {
    fn as_str(&self) -> &'static str {
        match self {
            XDownloadOptions::NoOpen => "noopen",
        }
    }
}

impl Display for XDownloadOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XDownloadOptions::NoOpen => write!(f, "noopen"),
        }
    }
}

impl From<XDownloadOptions> for Header {
    fn from(val: XDownloadOptions) -> Self {
        ("X-Download-Options", val.as_str().to_owned())
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
/// - allow-from: **Deprecated.** Ignored by all modern browsers. Use `ContentSecurityPolicy::new().frame_ancestors(...)` instead.
///
/// # Examples
///
/// ```
/// use helmet_core::XFrameOptions;
///
/// let x_frame_options = XFrameOptions::deny();
///
/// let x_frame_options = XFrameOptions::same_origin();
/// ```
#[derive(Clone)]
pub enum XFrameOptions {
    Deny,
    SameOrigin,
    #[deprecated(
        note = "ALLOW-FROM is ignored by modern browsers. Use ContentSecurityPolicy::new().frame_ancestors(...) instead."
    )]
    AllowFrom(String),
}

impl XFrameOptions {
    pub fn deny() -> Self {
        Self::Deny
    }

    pub fn same_origin() -> Self {
        Self::SameOrigin
    }

    #[deprecated(
        note = "ALLOW-FROM is ignored by modern browsers. Use ContentSecurityPolicy::new().frame_ancestors(...) instead."
    )]
    pub fn allow_from(uri: &str) -> Self {
        #[allow(deprecated)]
        Self::AllowFrom(uri.to_string())
    }
}

impl Display for XFrameOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(deprecated)]
        match self {
            XFrameOptions::Deny => write!(f, "DENY"),
            XFrameOptions::SameOrigin => write!(f, "SAMEORIGIN"),
            XFrameOptions::AllowFrom(uri) => write!(f, "ALLOW-FROM {}", uri),
        }
    }
}

impl From<XFrameOptions> for Header {
    fn from(val: XFrameOptions) -> Self {
        ("X-Frame-Options", val.to_string())
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

impl XPermittedCrossDomainPolicies {
    fn as_str(&self) -> &'static str {
        match self {
            XPermittedCrossDomainPolicies::None => "none",
            XPermittedCrossDomainPolicies::MasterOnly => "master-only",
            XPermittedCrossDomainPolicies::ByContentType => "by-content-type",
            XPermittedCrossDomainPolicies::ByFtpFilename => "by-ftp-filename",
            XPermittedCrossDomainPolicies::All => "all",
        }
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

impl From<XPermittedCrossDomainPolicies> for Header {
    fn from(val: XPermittedCrossDomainPolicies) -> Self {
        ("X-Permitted-Cross-Domain-Policies", val.as_str().to_owned())
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

impl From<XXSSProtection> for Header {
    fn from(val: XXSSProtection) -> Self {
        ("X-XSS-Protection", val.to_string())
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

impl From<XPoweredBy> for Header {
    fn from(val: XPoweredBy) -> Self {
        ("X-Powered-By", val.to_string())
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
/// - report-to: Specifies the endpoint name (defined via `Reporting-Endpoints` header) to send violation reports to.
/// - report-uri: Specifies URL(s) to send violation reports to (deprecated but still widely supported).
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
///
/// ## Report only
///
/// In report only mode, the browser will not block the request, but will send a report to the specified URI.
///
/// Make sure to set the `report-to` and/or `report-uri` directives.
///
/// ```
/// use helmet_core::ContentSecurityPolicy;
///
/// let content_security_policy = ContentSecurityPolicy::default()
///    .child_src(vec!["'self'", "https://youtube.com"])
///    .report_to("csp-endpoint")
///    .report_uri(vec!["https://example.com/report"])
///    .report_only();
/// ```
#[derive(Clone)]
pub struct ContentSecurityPolicy<'a> {
    child_src: Option<Vec<&'a str>>,
    connect_src: Option<Vec<&'a str>>,
    default_src: Option<Vec<&'a str>>,
    font_src: Option<Vec<&'a str>>,
    frame_src: Option<Vec<&'a str>>,
    img_src: Option<Vec<&'a str>>,
    manifest_src: Option<Vec<&'a str>>,
    media_src: Option<Vec<&'a str>>,
    object_src: Option<Vec<&'a str>>,
    prefetch_src: Option<Vec<&'a str>>,
    script_src: Option<Vec<&'a str>>,
    script_src_elem: Option<Vec<&'a str>>,
    script_src_attr: Option<Vec<&'a str>>,
    style_src: Option<Vec<&'a str>>,
    style_src_elem: Option<Vec<&'a str>>,
    style_src_attr: Option<Vec<&'a str>>,
    worker_src: Option<Vec<&'a str>>,
    base_uri: Option<Vec<&'a str>>,
    sandbox: Option<Vec<&'a str>>,
    form_action: Option<Vec<&'a str>>,
    frame_ancestors: Option<Vec<&'a str>>,
    report_to: Option<&'a str>,
    report_uri: Option<Vec<&'a str>>,
    require_trusted_types_for: Option<Vec<&'a str>>,
    trusted_types: Option<Vec<&'a str>>,
    upgrade_insecure_requests: bool,
    report_only: bool,
}

impl<'a> ContentSecurityPolicy<'a> {
    pub fn new() -> Self {
        Self {
            child_src: None,
            connect_src: None,
            default_src: None,
            font_src: None,
            frame_src: None,
            img_src: None,
            manifest_src: None,
            media_src: None,
            object_src: None,
            prefetch_src: None,
            script_src: None,
            script_src_elem: None,
            script_src_attr: None,
            style_src: None,
            style_src_elem: None,
            style_src_attr: None,
            worker_src: None,
            base_uri: None,
            sandbox: None,
            form_action: None,
            frame_ancestors: None,
            report_to: None,
            report_uri: None,
            require_trusted_types_for: None,
            trusted_types: None,
            upgrade_insecure_requests: false,
            report_only: false,
        }
    }

    /// child-src: Defines valid sources for web workers and nested browsing contexts loaded using elements such as `<frame>` and `<iframe>`.
    pub fn child_src(mut self, values: Vec<&'a str>) -> Self {
        self.child_src = Some(values);
        self
    }

    /// connect-src: Applies to XMLHttpRequest (AJAX), WebSocket or EventSource. If not allowed the browser emulates a 400 HTTP status code.
    pub fn connect_src(mut self, values: Vec<&'a str>) -> Self {
        self.connect_src = Some(values);
        self
    }

    /// default-src: The default-src is the default policy for loading content such as JavaScript, Images, CSS, Font's, AJAX requests, Frames, HTML5 Media. See the list of directives to see which values are allowed as default.
    pub fn default_src(mut self, values: Vec<&'a str>) -> Self {
        self.default_src = Some(values);
        self
    }

    /// font-src: Defines valid sources for fonts loaded using @font-face.
    pub fn font_src(mut self, values: Vec<&'a str>) -> Self {
        self.font_src = Some(values);
        self
    }

    /// frame-src: Defines valid sources for nested browsing contexts loading using elements such as `<frame>` and `<iframe>`.
    pub fn frame_src(mut self, values: Vec<&'a str>) -> Self {
        self.frame_src = Some(values);
        self
    }

    /// img-src: Defines valid sources of images and favicons.
    pub fn img_src(mut self, values: Vec<&'a str>) -> Self {
        self.img_src = Some(values);
        self
    }

    /// manifest-src: Specifies which manifest can be applied to the resource.
    pub fn manifest_src(mut self, values: Vec<&'a str>) -> Self {
        self.manifest_src = Some(values);
        self
    }

    /// media-src: Defines valid sources for loading media using the `<audio>` and `<video>` elements.
    pub fn media_src(mut self, values: Vec<&'a str>) -> Self {
        self.media_src = Some(values);
        self
    }

    /// object-src: Defines valid sources for the `<object>`, `<embed>`, and `<applet>` elements.
    pub fn object_src(mut self, values: Vec<&'a str>) -> Self {
        self.object_src = Some(values);
        self
    }

    /// prefetch-src: Specifies which referrer to use when fetching the resource.
    pub fn prefetch_src(mut self, values: Vec<&'a str>) -> Self {
        self.prefetch_src = Some(values);
        self
    }

    /// script-src: Defines valid sources for JavaScript.
    pub fn script_src(mut self, values: Vec<&'a str>) -> Self {
        self.script_src = Some(values);
        self
    }

    /// script-src-elem: Defines valid sources for JavaScript inline event handlers.
    pub fn script_src_elem(mut self, values: Vec<&'a str>) -> Self {
        self.script_src_elem = Some(values);
        self
    }

    /// script-src-attr: Defines valid sources for JavaScript inline event handlers.
    pub fn script_src_attr(mut self, values: Vec<&'a str>) -> Self {
        self.script_src_attr = Some(values);
        self
    }

    /// style-src: Defines valid sources for stylesheets.
    pub fn style_src(mut self, values: Vec<&'a str>) -> Self {
        self.style_src = Some(values);
        self
    }

    /// style-src-elem: Defines valid sources for stylesheets inline event handlers.
    pub fn style_src_elem(mut self, values: Vec<&'a str>) -> Self {
        self.style_src_elem = Some(values);
        self
    }

    /// style-src-attr: Defines valid sources for stylesheets inline event handlers.
    pub fn style_src_attr(mut self, values: Vec<&'a str>) -> Self {
        self.style_src_attr = Some(values);
        self
    }

    /// worker-src: Defines valid sources for Worker, SharedWorker, or ServiceWorker scripts.
    pub fn worker_src(mut self, values: Vec<&'a str>) -> Self {
        self.worker_src = Some(values);
        self
    }

    /// base-uri: Restricts the URLs which can be used in a document's `<base>` element.
    pub fn base_uri(mut self, values: Vec<&'a str>) -> Self {
        self.base_uri = Some(values);
        self
    }

    /// sandbox: Enables a sandbox for the requested resource similar to the iframe sandbox attribute. The sandbox applies a same origin policy, prevents popups, plugins and script execution is blocked. You can keep the sandbox value empty to keep all restrictions in place, or add values: allow-forms allow-same-origin allow-scripts allow-popups, allow-modals, allow-orientation-lock, allow-pointer-lock, allow-presentation, allow-popups-to-escape-sandbox, allow-top-navigation, allow-top-navigation-by-user-activation.
    pub fn sandbox(mut self, values: Vec<&'a str>) -> Self {
        self.sandbox = Some(values);
        self
    }

    /// form-action: Restricts the URLs which can be used as the target of a form submissions from a given context.
    pub fn form_action(mut self, values: Vec<&'a str>) -> Self {
        self.form_action = Some(values);
        self
    }

    /// frame-ancestors: Specifies valid parents that may embed a page using `<frame>`, `<iframe>`, `<object>`, `<embed>`, or `<applet>`.
    pub fn frame_ancestors(mut self, values: Vec<&'a str>) -> Self {
        self.frame_ancestors = Some(values);
        self
    }

    /// report-to: Specifies the endpoint name (defined via `Reporting-Endpoints` header) to send violation reports to.
    pub fn report_to(mut self, endpoint: &'a str) -> Self {
        self.report_to = Some(endpoint);
        self
    }

    /// report-uri: Specifies URL(s) to send violation reports to (deprecated but still widely supported).
    pub fn report_uri(mut self, values: Vec<&'a str>) -> Self {
        self.report_uri = Some(values);
        self
    }

    /// require-trusted-types-for: Specifies which trusted types are required by a resource.
    pub fn require_trusted_types_for(mut self, values: Vec<&'a str>) -> Self {
        self.require_trusted_types_for = Some(values);
        self
    }

    /// trusted-types: Specifies which trusted types are defined by a resource.
    pub fn trusted_types(mut self, values: Vec<&'a str>) -> Self {
        self.trusted_types = Some(values);
        self
    }

    /// Block HTTP requests on insecure elements.
    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.upgrade_insecure_requests = true;
        self
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

impl Display for ContentSecurityPolicy<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut directives: Vec<String> = Vec::new();
        let directive = |name: &str, values: &[&str]| format!("{} {}", name, values.join(" "));

        if let Some(v) = &self.default_src {
            directives.push(directive("default-src", v));
        }
        if let Some(v) = &self.base_uri {
            directives.push(directive("base-uri", v));
        }
        if let Some(v) = &self.child_src {
            directives.push(directive("child-src", v));
        }
        if let Some(v) = &self.connect_src {
            directives.push(directive("connect-src", v));
        }
        if let Some(v) = &self.font_src {
            directives.push(directive("font-src", v));
        }
        if let Some(v) = &self.form_action {
            directives.push(directive("form-action", v));
        }
        if let Some(v) = &self.frame_ancestors {
            directives.push(directive("frame-ancestors", v));
        }
        if let Some(v) = &self.frame_src {
            directives.push(directive("frame-src", v));
        }
        if let Some(v) = &self.img_src {
            directives.push(directive("img-src", v));
        }
        if let Some(v) = &self.manifest_src {
            directives.push(directive("manifest-src", v));
        }
        if let Some(v) = &self.media_src {
            directives.push(directive("media-src", v));
        }
        if let Some(v) = &self.object_src {
            directives.push(directive("object-src", v));
        }
        if let Some(v) = &self.prefetch_src {
            directives.push(directive("prefetch-src", v));
        }
        if let Some(v) = &self.script_src {
            directives.push(directive("script-src", v));
        }
        if let Some(v) = &self.script_src_elem {
            directives.push(directive("script-src-elem", v));
        }
        if let Some(v) = &self.script_src_attr {
            directives.push(directive("script-src-attr", v));
        }
        if let Some(v) = &self.style_src {
            directives.push(directive("style-src", v));
        }
        if let Some(v) = &self.style_src_elem {
            directives.push(directive("style-src-elem", v));
        }
        if let Some(v) = &self.style_src_attr {
            directives.push(directive("style-src-attr", v));
        }
        if let Some(v) = &self.worker_src {
            directives.push(directive("worker-src", v));
        }
        if let Some(v) = &self.sandbox {
            directives.push(directive("sandbox", v));
        }
        if let Some(v) = &self.report_to {
            directives.push(format!("report-to {}", v));
        }
        if let Some(v) = &self.report_uri {
            directives.push(directive("report-uri", v));
        }
        if let Some(v) = &self.require_trusted_types_for {
            directives.push(directive("require-trusted-types-for", v));
        }
        if let Some(v) = &self.trusted_types {
            directives.push(directive("trusted-types", v));
        }
        if self.upgrade_insecure_requests {
            directives.push("upgrade-insecure-requests".to_string());
        }

        write!(f, "{}", directives.join("; "))
    }
}

impl Default for ContentSecurityPolicy<'_> {
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

impl From<ContentSecurityPolicy<'_>> for Header {
    fn from(val: ContentSecurityPolicy<'_>) -> Self {
        (
            if val.report_only {
                "Content-Security-Policy-Report-Only"
            } else {
                "Content-Security-Policy"
            },
            val.to_string(),
        )
    }
}

/// Error returned when a header name or value cannot be converted to a valid HTTP header.
#[derive(Debug)]
pub enum HelmetError {
    /// The header name is not a valid HTTP header name.
    InvalidHeaderName(String),
    /// The header value is not a valid HTTP header value.
    InvalidHeaderValue(String),
}

impl std::fmt::Display for HelmetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HelmetError::InvalidHeaderName(name) => write!(f, "invalid header name: {}", name),
            HelmetError::InvalidHeaderValue(msg) => write!(f, "invalid header value: {}", msg),
        }
    }
}

impl std::error::Error for HelmetError {}

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
#[derive(Clone)]
pub struct Helmet {
    pub headers: Vec<Header>,
}

#[allow(clippy::should_implement_trait)]
impl Helmet {
    /// Create new `Helmet` instance without any headers applied
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
        }
    }

    /// Add header to the middleware
    pub fn add(mut self, header: impl Into<Header>) -> Self {
        self.headers.push(header.into());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_default_output() {
        assert_eq!(
            ContentSecurityPolicy::default().to_string(),
            "default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests"
        );
    }

    #[test]
    fn csp_default_override_replaces_directive() {
        assert_eq!(
            ContentSecurityPolicy::default()
                .script_src(vec!["'self'", "'unsafe-inline'", "'unsafe-eval'"])
                .to_string(),
            "default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'self'; img-src 'self' data:; object-src 'none'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests"
        );
    }

    #[test]
    fn csp_default_override_multiple_directives() {
        assert_eq!(
            ContentSecurityPolicy::default()
                .script_src(vec!["'self'", "'unsafe-inline'"])
                .img_src(vec!["*"])
                .to_string(),
            "default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'self'; img-src *; object-src 'none'; script-src 'self' 'unsafe-inline'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests"
        );
    }

    #[test]
    fn csp_new_is_empty() {
        assert_eq!(ContentSecurityPolicy::new().to_string(), "");
    }
}
