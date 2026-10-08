//! edns: a tiny authoritative DNS server plus HTTP service that tells you
//! which recursive resolver your device uses, and whether it forwards an EDNS
//! Client Subnet (ECS) option to authoritative servers.

mod certstore;
mod clock;
mod config;
mod dns;
mod http;
mod limit;
mod net;
mod store;
mod tls;
mod token;

use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinSet;

use crate::certstore::CertStorage;
use crate::config::{CertStoreKind, Config, StoreKind};
use crate::net::Listener;
use crate::store::{MemStore, RedisStore, Store};

#[tokio::main]
async fn main() -> ExitCode {
    // Colour only on a terminal: `fly logs` and docker show escape codes raw.
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    // One process-wide TLS backend, for the HTTPS server, the ACME client and
    // rediss:// connections alike.
    let _ = rustls::crypto::ring::default_provider().install_default();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let cfg = Arc::new(Config::from_env().context("config")?);
    let store = Arc::new(match cfg.store {
        StoreKind::Memory => Store::Memory(MemStore::default()),
        StoreKind::Redis => Store::Redis(RedisStore::new(&cfg.redis_conn_url())?),
    });

    // Bind everything up front, so a bad address fails startup loudly.
    let dns_h = Arc::new(dns::DnsHandler::new(cfg.clone(), store.clone()));
    // UDP may need its own bind address: on Fly.io it must listen on
    // fly-global-services so replies leave from the anycast IP.
    let udp = net::bind_udp(&cfg.dns_udp_addr).await.with_context(|| format!("dns udp {}", cfg.dns_udp_addr))?;
    let dns_tcp = Listener::bind(&cfg.dns_addr, cfg.proxy_protocol, dns::MAX_TCP_CONNS)
        .await
        .with_context(|| format!("dns tcp {}", cfg.dns_addr))?;
    let http_h = Arc::new(http::HttpHandler::new(cfg.clone(), store.clone()));
    let http_ln = Listener::bind(&cfg.http_addr, cfg.proxy_protocol, http::MAX_CONNS)
        .await
        .with_context(|| format!("http {}", cfg.http_addr))?;
    tracing::info!("DNS listening on {}/udp and {}/tcp", udp.local_addr()?, dns_tcp.local_addr()?);
    tracing::info!("HTTP listening on {} (base={} a={})", http_ln.local_addr()?, cfg.base_domain, cfg.http_ip);

    // One DNS handler for both transports: its UDP and TCP rate limits are
    // already separate, and the capture guard must see every capture.
    let mut tasks = JoinSet::new();
    tasks.spawn({
        let h = dns_h.clone();
        async move { dns::serve_udp(h, udp).await.context("dns udp") }
    });
    tasks.spawn(async move { dns::serve_tcp(dns_h, dns_tcp).await.context("dns tcp") });
    tasks.spawn({
        let h = http_h.clone();
        async move { http::serve(h, http_ln, None).await.context("http") }
    });

    // HTTPS: the certificate is obtained and renewed in the background via an
    // in-process DNS-01 solver (we are the authoritative server for the zone).
    if cfg.enable_tls {
        let storage = match cfg.cert_store {
            CertStoreKind::File => CertStorage::file(&cfg.cert_dir),
            CertStoreKind::Redis => CertStorage::redis(&cfg.redis_conn_url())?,
        };
        let certs = Arc::new(tls::CertManager::new(cfg.clone(), store.clone(), storage));
        let acceptor = tokio_rustls::TlsAcceptor::from(certs.clone().server_config()?);
        let https_ln = Listener::bind(&cfg.https_addr, cfg.proxy_protocol, http::MAX_CONNS)
            .await
            .with_context(|| format!("https {}", cfg.https_addr))?;
        tracing::info!("HTTPS listening on {}", https_ln.local_addr()?);
        tasks.spawn(async move {
            certs.run().await;
            Ok(())
        });
        tasks.spawn(async move { http::serve(http_h, https_ln, Some(acceptor)).await.context("https") });
    }

    // Run until a server fails or we're told to stop. As PID 1 in a
    // container, signals have no default action, so handle them explicitly.
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        res = tasks.join_next() => match res {
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(e).context("server task"),
            Some(Ok(Ok(()))) | None => anyhow::bail!("server exited"),
        },
        _ = term.recv() => { tracing::info!("SIGTERM, exiting"); Ok(()) }
        _ = int.recv() => { tracing::info!("SIGINT, exiting"); Ok(()) }
    }
}
