use crate::{
    HttpContext, HttpHandler, RequestOrResponse, TlsFailureStage, WebSocketContext,
    WebSocketHandler,
    body::Body,
    certificate_authority::{CertificateAuthority, UpstreamCertificateInfo},
    rewind::Rewind,
};
use futures::{Sink, Stream, StreamExt};
use http::uri::{Authority, Scheme};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::{Bytes, Incoming},
    header::{Entry, SEC_WEBSOCKET_EXTENSIONS},
    service::service_fn,
    upgrade::Upgraded,
};
use hyper_util::{
    client::legacy::{Client, connect::Connect},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::{io::AsyncReadExt, net::TcpStream, task::JoinHandle};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{
    Connector, WebSocketStream,
    tungstenite::{self, Message},
};
use tracing::{Instrument, Span, error, info_span, instrument, warn};
#[cfg(feature = "rustls-client")]
use x509_parser::{extensions::GeneralName, prelude::FromDer};

#[cfg(feature = "rustls-client")]
async fn sniff_upstream_certificate(
    authority: &Authority,
) -> Result<UpstreamCertificateInfo, String> {
    use tokio_rustls::{
        TlsConnector,
        rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
    };

    let stream = TcpStream::connect(authority.as_ref())
        .await
        .map_err(|error| format!("upstream_tcp_connect_failed:{error}"))?;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| format!("rustls_provider_init_failed:{error}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(authority.host().to_string())
        .map_err(|error| format!("invalid_server_name:{error}"))?;

    let stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| format!("upstream_tls_handshake_failed:{error}"))?;

    let (_, session) = stream.get_ref();
    let certificate = session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .cloned()
        .ok_or_else(|| "upstream_tls_no_peer_certificate".to_string())?;

    parse_upstream_certificate(&certificate)
}

#[cfg(feature = "rustls-client")]
fn parse_upstream_certificate(
    cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
) -> Result<UpstreamCertificateInfo, String> {
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
        .map_err(|error| format!("upstream_cert_parse_failed:{error}"))?;

    let common_name = parsed
        .subject()
        .iter_common_name()
        .find_map(|entry| entry.as_str().ok())
        .map(ToString::to_string);

    let mut dns_names = Vec::new();
    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::DNSName(name) = name {
                let normalized = name.to_ascii_lowercase();
                if !dns_names.iter().any(|existing| existing == &normalized) {
                    dns_names.push(normalized);
                }
            }
        }
    }

    Ok(UpstreamCertificateInfo {
        dns_names,
        common_name,
    })
}

fn bad_request() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .expect("Failed to build response")
}

fn strip_unsupported_websocket_extensions<T>(req: &mut Request<T>) {
    // `tokio-tungstenite` in this build does not negotiate permessage-deflate.
    // Remove extension offers so peers do not send RSV-compressed frames.
    req.headers_mut().remove(SEC_WEBSOCKET_EXTENSIONS);
}

fn spawn_with_trace<T: Send + Sync + 'static>(
    fut: impl Future<Output = T> + Send + 'static,
    span: Span,
) -> JoinHandle<T> {
    tokio::spawn(fut.instrument(span))
}

pub(crate) struct InternalProxy<C, CA, H, W> {
    pub ca: Arc<CA>,
    pub client: Client<C, Body>,
    pub server: ServerBuilder<TokioExecutor>,
    pub http_handler: H,
    pub websocket_handler: W,
    pub websocket_connector: Option<Connector>,
    pub upstream_cert_sniffing: bool,
    pub client_addr: SocketAddr,
}

impl<C, CA, H, W> Clone for InternalProxy<C, CA, H, W>
where
    C: Clone,
    H: Clone,
    W: Clone,
{
    fn clone(&self) -> Self {
        InternalProxy {
            ca: Arc::clone(&self.ca),
            client: self.client.clone(),
            server: self.server.clone(),
            http_handler: self.http_handler.clone(),
            websocket_handler: self.websocket_handler.clone(),
            websocket_connector: self.websocket_connector.clone(),
            upstream_cert_sniffing: self.upstream_cert_sniffing,
            client_addr: self.client_addr,
        }
    }
}

impl<C, CA, H, W> InternalProxy<C, CA, H, W>
where
    C: Connect + Clone + Send + Sync + 'static,
    CA: CertificateAuthority,
    H: HttpHandler,
    W: WebSocketHandler,
{
    fn context(&self) -> HttpContext {
        HttpContext {
            client_addr: self.client_addr,
        }
    }

    async fn notify_tls_failure(
        &mut self,
        authority: Option<&Authority>,
        stage: TlsFailureStage,
        error_text: &str,
    ) {
        self.http_handler
            .handle_tls_failure(&self.context(), authority, stage, error_text)
            .await;
    }

    #[cfg(feature = "rustls-client")]
    async fn sniff_upstream_certificate(
        &mut self,
        authority: &Authority,
    ) -> Option<UpstreamCertificateInfo> {
        match sniff_upstream_certificate(authority).await {
            Ok(info) => Some(info),
            Err(error_text) => {
                self.notify_tls_failure(
                    Some(authority),
                    TlsFailureStage::UpstreamCertSniff,
                    &error_text,
                )
                .await;
                None
            }
        }
    }

    #[cfg(not(feature = "rustls-client"))]
    async fn sniff_upstream_certificate(
        &mut self,
        _authority: &Authority,
    ) -> Option<UpstreamCertificateInfo> {
        None
    }

    #[instrument(
        skip_all,
        fields(
            version = ?req.version(),
            method = %req.method(),
            uri=%req.uri(),
            client_addr = %self.client_addr,
        )
    )]
    pub(crate) async fn proxy(
        mut self,
        req: Request<Incoming>,
    ) -> Result<Response<Body>, Infallible> {
        let ctx = self.context();

        let req = match self
            .http_handler
            .handle_request(&ctx, req.map(Body::from))
            .instrument(info_span!("handle_request"))
            .await
        {
            RequestOrResponse::Request(req) => req,
            RequestOrResponse::Response(res) => return Ok(res),
        };

        if req.method() == Method::CONNECT {
            Ok(self.process_connect(req))
        } else if hyper_tungstenite::is_upgrade_request(&req) {
            Ok(self.upgrade_websocket(req))
        } else {
            let res = self
                .client
                .request(normalize_request(req))
                .instrument(info_span!("proxy_request"))
                .await;

            match res {
                Ok(res) => Ok(self
                    .http_handler
                    .handle_response(&ctx, res.map(Body::from))
                    .instrument(info_span!("handle_response"))
                    .await),
                Err(err) => Ok(self
                    .http_handler
                    .handle_error(&ctx, err)
                    .instrument(info_span!("handle_error"))
                    .await),
            }
        }
    }

    fn process_connect(mut self, mut req: Request<Body>) -> Response<Body> {
        match req.uri().authority().cloned() {
            Some(authority) => {
                let span = info_span!("process_connect");
                let fut = async move {
                    match hyper::upgrade::on(&mut req).await {
                        Ok(upgraded) => {
                            let mut upgraded = TokioIo::new(upgraded);
                            let mut buffer = [0; 4];
                            let bytes_read = match upgraded.read(&mut buffer).await {
                                Ok(bytes_read) => bytes_read,
                                Err(e) => {
                                    let error_text = e.to_string();
                                    self.notify_tls_failure(
                                        Some(&authority),
                                        TlsFailureStage::ClientHelloRead,
                                        &error_text,
                                    )
                                    .await;
                                    error!("Failed to read from upgraded connection: {}", e);
                                    return;
                                }
                            };

                            let mut upgraded = Rewind::new(
                                upgraded,
                                Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                            );

                            if self
                                .http_handler
                                .should_intercept(&self.context(), &req)
                                .await
                            {
                                if buffer == *b"GET " {
                                    if let Err(e) = self
                                        .serve_stream(
                                            TokioIo::new(upgraded),
                                            Scheme::HTTP,
                                            authority,
                                        )
                                        .await
                                    {
                                        error!("WebSocket connect error: {}", e);
                                    }

                                    return;
                                } else if buffer[..2] == *b"\x16\x03" {
                                    let upstream_certificate = if self.upstream_cert_sniffing {
                                        self.sniff_upstream_certificate(&authority).await
                                    } else {
                                        None
                                    };

                                    let server_config = self
                                        .ca
                                        .gen_server_config_with_upstream(
                                            &authority,
                                            upstream_certificate.as_ref(),
                                        )
                                        .instrument(info_span!("gen_server_config"))
                                        .await;

                                    let stream = match TlsAcceptor::from(server_config)
                                        .accept(upgraded)
                                        .await
                                    {
                                        Ok(stream) => TokioIo::new(stream),
                                        Err(e) => {
                                            let error_text = e.to_string();
                                            self.notify_tls_failure(
                                                Some(&authority),
                                                TlsFailureStage::ClientHandshake,
                                                &error_text,
                                            )
                                            .await;
                                            error!("Failed to establish TLS connection: {}", e);
                                            return;
                                        }
                                    };

                                    let mut tls_failure_notifier = self.clone();
                                    let authority_for_error = authority.clone();
                                    if let Err(e) =
                                        self.serve_stream(stream, Scheme::HTTPS, authority).await
                                    {
                                        if !e
                                            .to_string()
                                            .starts_with("error shutting down connection")
                                        {
                                            let error_text = e.to_string();
                                            tls_failure_notifier
                                                .notify_tls_failure(
                                                    Some(&authority_for_error),
                                                    TlsFailureStage::UpstreamConnect,
                                                    &error_text,
                                                )
                                                .await;
                                            error!("HTTPS connect error: {}", e);
                                        }
                                    }

                                    return;
                                } else {
                                    warn!(
                                        "Unknown protocol, read '{:02X?}' from upgraded connection",
                                        &buffer[..bytes_read]
                                    );
                                }
                            }

                            let mut server = match TcpStream::connect(authority.as_ref()).await {
                                Ok(server) => server,
                                Err(e) => {
                                    let error_text = e.to_string();
                                    self.notify_tls_failure(
                                        Some(&authority),
                                        TlsFailureStage::UpstreamConnect,
                                        &error_text,
                                    )
                                    .await;
                                    error!("Failed to connect to {}: {}", authority, e);
                                    return;
                                }
                            };

                            if let Err(e) =
                                tokio::io::copy_bidirectional(&mut upgraded, &mut server).await
                            {
                                let error_text = e.to_string();
                                self.notify_tls_failure(
                                    Some(&authority),
                                    TlsFailureStage::TunnelCopy,
                                    &error_text,
                                )
                                .await;
                                error!("Failed to tunnel to {}: {}", authority, e);
                            }
                        }
                        Err(e) => error!("Upgrade error: {}", e),
                    };
                };

                spawn_with_trace(fut, span);
                Response::new(Body::empty())
            }
            None => bad_request(),
        }
    }

    #[instrument(skip_all)]
    fn upgrade_websocket(self, req: Request<Body>) -> Response<Body> {
        let mut req = {
            let (mut parts, _) = req.into_parts();

            parts.uri = {
                let mut parts = parts.uri.into_parts();

                parts.scheme = if parts.scheme.unwrap_or(Scheme::HTTP) == Scheme::HTTP {
                    Some("ws".try_into().expect("Failed to convert scheme"))
                } else {
                    Some("wss".try_into().expect("Failed to convert scheme"))
                };

                match Uri::from_parts(parts) {
                    Ok(uri) => uri,
                    Err(_) => {
                        return bad_request();
                    }
                }
            };

            Request::from_parts(parts, ())
        };
        strip_unsupported_websocket_extensions(&mut req);

        match hyper_tungstenite::upgrade(&mut req, None) {
            Ok((res, websocket)) => {
                let span = info_span!("websocket");
                let fut = async move {
                    match websocket.await {
                        Ok(ws) => {
                            if let Err(e) = self.handle_websocket(ws, req).await {
                                error!("Failed to handle WebSocket: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to upgrade to WebSocket: {}", e);
                        }
                    }
                };

                spawn_with_trace(fut, span);
                res.map(Body::from)
            }
            Err(_) => bad_request(),
        }
    }

    #[instrument(skip_all)]
    async fn handle_websocket(
        self,
        client_socket: WebSocketStream<TokioIo<Upgraded>>,
        req: Request<()>,
    ) -> Result<(), tungstenite::Error> {
        let uri = req.uri().clone();

        #[cfg(any(feature = "rustls-client", feature = "native-tls-client"))]
        let (server_socket, _) = tokio_tungstenite::connect_async_tls_with_config(
            req,
            None,
            false,
            self.websocket_connector,
        )
        .await?;

        #[cfg(not(any(feature = "rustls-client", feature = "native-tls-client")))]
        let (server_socket, _) = tokio_tungstenite::connect_async(req).await?;

        let (server_sink, server_stream) = server_socket.split();
        let (client_sink, client_stream) = client_socket.split();

        let InternalProxy {
            websocket_handler, ..
        } = self;

        spawn_message_forwarder(
            server_stream,
            client_sink,
            websocket_handler.clone(),
            WebSocketContext::ServerToClient {
                src: uri.clone(),
                dst: self.client_addr,
            },
        );

        spawn_message_forwarder(
            client_stream,
            server_sink,
            websocket_handler,
            WebSocketContext::ClientToServer {
                src: self.client_addr,
                dst: uri,
            },
        );

        Ok(())
    }

    #[instrument(skip_all)]
    async fn serve_stream<I>(
        self,
        stream: I,
        scheme: Scheme,
        authority: Authority,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
        let service = service_fn(|mut req| {
            if req.version() == hyper::Version::HTTP_10 || req.version() == hyper::Version::HTTP_11
            {
                let (mut parts, body) = req.into_parts();

                parts.uri = {
                    let mut parts = parts.uri.into_parts();
                    parts.scheme = Some(scheme.clone());
                    parts.authority = Some(authority.clone());
                    Uri::from_parts(parts).expect("Failed to build URI")
                };

                req = Request::from_parts(parts, body);
            };

            self.clone().proxy(req)
        });

        self.server
            .serve_connection_with_upgrades(stream, service)
            .await
    }
}

fn spawn_message_forwarder(
    stream: impl Stream<Item = Result<Message, tungstenite::Error>> + Unpin + Send + 'static,
    sink: impl Sink<Message, Error = tungstenite::Error> + Unpin + Send + 'static,
    handler: impl WebSocketHandler,
    ctx: WebSocketContext,
) {
    let span = info_span!("message_forwarder", context = ?ctx);
    let fut = handler.handle_websocket(ctx, stream, sink);
    spawn_with_trace(fut, span);
}

#[instrument(skip_all)]
fn normalize_request<T>(mut req: Request<T>) -> Request<T> {
    // Hyper will automatically add a Host header if needed.
    req.headers_mut().remove(hyper::header::HOST);

    // HTTP/2 supports multiple cookie headers, but HTTP/1.x only supports one.
    if let Entry::Occupied(mut cookies) = req.headers_mut().entry(hyper::header::COOKIE) {
        let joined_cookies = bstr::join(b"; ", cookies.iter());
        cookies.insert(joined_cookies.try_into().expect("Failed to join cookies"));
    }

    *req.version_mut() = hyper::Version::HTTP_11;
    req
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_util::client::legacy::connect::HttpConnector;
    use tokio_rustls::rustls::ServerConfig;

    struct CA;

    impl CertificateAuthority for CA {
        async fn gen_server_config(&self, _authority: &Authority) -> Arc<ServerConfig> {
            unimplemented!();
        }
    }

    fn build_proxy() -> InternalProxy<HttpConnector, CA, crate::NoopHandler, crate::NoopHandler> {
        InternalProxy {
            ca: Arc::new(CA),
            client: Client::builder(TokioExecutor::new()).build(HttpConnector::new()),
            server: ServerBuilder::new(TokioExecutor::new()),
            http_handler: crate::NoopHandler::new(),
            websocket_handler: crate::NoopHandler::new(),
            websocket_connector: None,
            upstream_cert_sniffing: false,
            client_addr: "127.0.0.1:8080".parse().unwrap(),
        }
    }

    mod bad_request {
        use super::*;

        #[test]
        fn correct_status() {
            let res = bad_request();
            assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        }
    }

    mod normalize_request {
        use super::*;

        #[test]
        fn removes_host_header() {
            let req = Request::builder()
                .uri("http://example.com/")
                .header(hyper::header::HOST, "example.com")
                .body(())
                .unwrap();

            let req = normalize_request(req);

            assert_eq!(req.headers().get(hyper::header::HOST), None);
        }

        #[test]
        fn joins_cookies() {
            let req = Request::builder()
                .uri("http://example.com/")
                .header(hyper::header::COOKIE, "foo=bar")
                .header(hyper::header::COOKIE, "baz=qux")
                .body(())
                .unwrap();

            let req = normalize_request(req);

            assert_eq!(
                req.headers().get_all(hyper::header::COOKIE).iter().count(),
                1
            );

            assert_eq!(
                req.headers().get(hyper::header::COOKIE),
                Some(&"foo=bar; baz=qux".parse().unwrap())
            );
        }
    }

    mod strip_unsupported_websocket_extensions {
        use super::*;

        #[test]
        fn removes_extension_offer_header() {
            let mut req = Request::builder()
                .uri("wss://example.com/socket")
                .header(
                    SEC_WEBSOCKET_EXTENSIONS,
                    "permessage-deflate; client_max_window_bits",
                )
                .body(())
                .unwrap();

            strip_unsupported_websocket_extensions(&mut req);

            assert!(req.headers().get(SEC_WEBSOCKET_EXTENSIONS).is_none());
        }
    }

    mod process_connect {
        use super::*;

        #[test]
        fn returns_bad_request_if_missing_authority() {
            let proxy = build_proxy();

            let req = Request::builder()
                .uri("/foo/bar?baz")
                .body(Body::empty())
                .unwrap();

            let res = proxy.process_connect(req);

            assert_eq!(res.status(), StatusCode::BAD_REQUEST)
        }
    }

    mod upgrade_websocket {
        use super::*;

        #[test]
        fn returns_bad_request_if_missing_authority() {
            let proxy = build_proxy();

            let req = Request::builder()
                .uri("/foo/bar?baz")
                .body(Body::empty())
                .unwrap();

            let res = proxy.upgrade_websocket(req);

            assert_eq!(res.status(), StatusCode::BAD_REQUEST)
        }

        #[test]
        fn returns_bad_request_if_missing_headers() {
            let proxy = build_proxy();

            let req = Request::builder()
                .uri("http://example.com/foo/bar?baz")
                .body(Body::empty())
                .unwrap();

            let res = proxy.upgrade_websocket(req);

            assert_eq!(res.status(), StatusCode::BAD_REQUEST)
        }
    }
}
