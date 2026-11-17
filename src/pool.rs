//! Upstream connection pool: connects to all configured servers in parallel.

use crate::config::{Config, ServerConfig};
use anyhow::{Context, Result, anyhow};
use rmcp::{
    ServiceExt,
    model::Tool,
    service::{RoleClient, RunningService},
    transport::{
        StreamableHttpClientTransport, TokioChildProcess,
        streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use std::{collections::BTreeMap, time::Duration};
use tokio::process::Command;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

pub type Client = RunningService<RoleClient, ()>;

pub struct Upstream {
    pub client: Client,
    pub tools: Vec<Tool>,
}

#[derive(Default)]
pub struct Pool {
    pub servers: BTreeMap<String, Upstream>,
    /// Servers that failed to connect, with the reason (reported by `doctor`).
    pub failures: BTreeMap<String, String>,
}

async fn connect_one(name: &str, cfg: &ServerConfig) -> Result<Upstream> {
    let client: Client = if let Some(cmd) = &cfg.command {
        let mut c = Command::new(cmd);
        c.args(&cfg.args).envs(crate::auth::stdio_env(cfg).await?);
        ().serve(TokioChildProcess::new(c)?)
            .await
            .context("stdio handshake")?
    } else if let Some(url) = &cfg.url {
        if cfg.transport.as_deref() == Some("sse") {
            // Legacy HTTP+SSE: static credentials only (headers/bearer/query); OAuth needs streamable HTTP.
            if matches!(
                crate::auth::parse_auth(cfg)?,
                crate::auth::AuthConfig::Oauth(_)
                    | crate::auth::AuthConfig::ClientCredentials { .. }
            ) {
                return Err(anyhow!(
                    "OAuth is not supported over legacy SSE; use transport \"http\" or a static credential"
                ));
            }
            let creds = crate::auth::http_creds(cfg).await?;
            let t = crate::sse::connect(
                &crate::auth::with_query(url, &creds.query),
                creds.headers,
                creds.bearer,
            )
            .await?;
            let client: Client = ().serve(t).await.context("sse handshake")?;
            let tools = client.list_all_tools().await.context("tools/list")?;
            return Ok(Upstream { client, tools });
        }
        let kind = crate::auth::parse_auth(cfg)?;
        if matches!(
            kind,
            crate::auth::AuthConfig::Oauth(_) | crate::auth::AuthConfig::ClientCredentials { .. }
        ) {
            let mut tc = StreamableHttpClientTransportConfig::with_uri(url.as_str());
            let mut headers = std::collections::HashMap::new();
            for (k, v) in &cfg.headers {
                headers.insert(
                    http::HeaderName::from_bytes(k.as_bytes())?,
                    http::HeaderValue::from_str(&crate::auth::resolve_secret(v).await?)?,
                );
            }
            tc = tc.custom_headers(headers);
            let t = if matches!(kind, crate::auth::AuthConfig::Oauth(_)) {
                crate::oauth::connect_transport(name, cfg, tc).await?
            } else {
                crate::oauth::connect_client_credentials(name, cfg, tc).await?
            };
            let client: Client = ().serve(t).await.context("http handshake")?;
            let tools = client.list_all_tools().await.context("tools/list")?;
            return Ok(Upstream { client, tools });
        }
        let creds = crate::auth::http_creds(cfg).await?;
        let mut tc = StreamableHttpClientTransportConfig::with_uri(crate::auth::with_query(
            url,
            &creds.query,
        ));
        if let Some(t) = creds.bearer {
            tc = tc.auth_header(t);
        }
        tc = tc.custom_headers(creds.headers);
        ().serve(StreamableHttpClientTransport::from_config(tc))
            .await
            .context("http handshake")?
    } else {
        return Err(anyhow!("server needs `command` or `url`"));
    };
    let tools = client.list_all_tools().await.context("tools/list")?;
    Ok(Upstream { client, tools })
}

impl Pool {
    pub async fn connect(cfg: &Config) -> Pool {
        let tasks: Vec<_> = cfg
            .servers
            .iter()
            .map(|(name, sc)| {
                let (name, sc) = (name.clone(), sc.clone());
                tokio::spawn(async move {
                    let r = match tokio::time::timeout(CONNECT_TIMEOUT, connect_one(&name, &sc))
                        .await
                    {
                        Ok(r) => r.map_err(|e| format!("{e:#}")),
                        Err(_) => Err(format!("timed out after {}s", CONNECT_TIMEOUT.as_secs())),
                    };
                    (name, r)
                })
            })
            .collect();
        let mut pool = Pool::default();
        for t in tasks {
            if let Ok((name, r)) = t.await {
                match r {
                    Ok(u) => {
                        pool.servers.insert(name, u);
                    }
                    Err(e) => {
                        pool.failures.insert(name, e);
                    }
                }
            }
        }
        pool
    }
}
