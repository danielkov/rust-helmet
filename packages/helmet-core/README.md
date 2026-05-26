# `helmet-core` - Security Middleware for popular Rust web frameworks

[![crate](https://img.shields.io/crates/v/helmet-core.svg)](https://crates.io/crates/helmet-core)
[![docs](https://docs.rs/helmet-core/badge.svg)](https://docs.rs/helmet-core)

- `ntex-helmet` is a security middleware for the `ntex` web framework.
- `actix-web-helmet` is a security middleware for the `actix-web` web framework.
- `rocket-helmet` is a security middleware for the `rocket` web framework.
- `warp-helmet` is a security middleware for the `warp` web framework.
- `axum-helmet` is a security middleware for the `axum` web framework.
- `poem-helmet` is a security middleware for the `poem` web framework.
- `salvo-helmet` is a security middleware for the `salvo` web framework.
- `tide-helmet` is a security middleware for the `tide` web framework.

It works by setting HTTP headers for you. These headers can help protect your app from some well-known web vulnerabilities:

- [Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)
- [Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)
- [Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)
- [Origin-Agent-Cluster](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster)
- [Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)
- [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)
- [X-DNS-Prefetch-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control)
- [X-Download-Options](<https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/ms537628(v=vs.85)?redirectedfrom=MSDN>)
- [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [X-Permitted-Cross-Domain-Policies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Permitted-Cross-Domain-Policies)
- [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)
- [X-Powered-By](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Powered-By)
- [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
helmet-core = "1.0.1"
```

Implementing the middleware is different for each framework. See the README for your framework of choice to see how to use it.

## Example

If your framework already has a `*-helmet` crate, prefer that. Otherwise, you
can wrap `helmet_core::Helmet` yourself — the `headers` field is a
`Vec<(&'static str, String)>` that you copy onto each response.

```rust,ignore
use helmet_core::Helmet;

let helmet = Helmet::default();

struct MyFrameworkMiddleware(Helmet);

impl<S, B> Middleware<S, B> for MyFrameworkMiddleware {
    fn on_response(&self, res: &mut Response<B>) {
        for (name, value) in &self.0.headers {
            res.headers_mut().insert(*name, value.clone());
        }
    }
}
```

## License

This project is licensed under the [MIT license](LICENSE).
