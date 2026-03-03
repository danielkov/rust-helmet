# `poem-helmet` - Security Middleware for the Poem web framework

[![crate](https://img.shields.io/crates/v/poem-helmet.svg)](https://crates.io/crates/poem-helmet)
[![docs](https://docs.rs/poem-helmet/badge.svg)](https://docs.rs/poem-helmet)

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
poem-helmet = "0.3"
```

## Example

```rust
use poem::{get, handler, listener::TcpListener, EndpointExt, Route, Server};
use poem_helmet::Helmet;

#[handler]
fn index() -> &'static str {
    "Hello, world!"
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/", get(index))
        .with(Helmet::default());

    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await
}
```

## License

This project is licensed under the [MIT license](LICENSE).
