# `salvo-helmet` - Security Middleware for the Salvo web framework

[![crate](https://img.shields.io/crates/v/salvo-helmet.svg)](https://crates.io/crates/salvo-helmet)
[![docs](https://docs.rs/salvo-helmet/badge.svg)](https://docs.rs/salvo-helmet)

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
salvo-helmet = "0.3"
```

## Example

```rust
use salvo::prelude::*;
use salvo_helmet::Helmet;

#[handler]
async fn index() -> &'static str {
    "Hello, world!"
}

#[tokio::main]
async fn main() {
    let router = Router::with_hoop(Helmet::default())
        .get(index);

    let acceptor = TcpListener::new("0.0.0.0:3000").bind().await;
    Server::new(acceptor).serve(router).await;
}
```

## License

This project is licensed under the [MIT license](LICENSE).
