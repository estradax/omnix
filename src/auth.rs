//! Authentication. Credentials are resolved host-side and attached when proxying;
//! the sandbox never sees them. This module covers static methods (none, bearer,
//! basic, header, query) and secret references; OAuth flows are added separately.

use crate::config::ServerConfig;
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use http::{HeaderName, HeaderValue};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    None,
    Bearer {
        token: String,
    },
    Basic {
        username: String,
        password: String,
    },
    Header {
        name: String,
        value: String,
    },
    Query {
        name: String,
        value: String,
    },
    /// OAuth 2.1 authorization code + PKCE; needs `omnix login <server>`.
    Oauth(OauthConfig),
    /// Machine-to-machine (MCP client-credentials extension).
    ClientCredentials {
        client_id: String,
        /// Secret reference for `client_secret` auth.
        client_secret: Option<String>,
        /// Secret reference (`file:`/`env:`/`cmd:`) holding a PEM private key for `private_key_jwt`.
        private_key: Option<String>,
        /// RS256 | RS384 | RS512 | ES256 | ES384 (default RS256)
        algorithm: Option<String>,
        #[serde(default)]
        scopes: Vec<String>,
    },
    #[serde(other)]
    Unsupported,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OauthConfig {
    /// Pre-registered client (needed for servers without DCR/CIMD, e.g. GitHub).
    pub client_id: Option<String>,
    /// Secret reference (`env:`, `cmd:`, ...) for a pre-registered confidential client.
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    /// HTTPS URL of a Client ID Metadata Document.
    pub client_metadata_url: Option<String>,
    pub client_name: Option<String>,
    /// "device" makes `omnix login` use RFC 8628 (non-spec extension; needs `client_id`).
    pub flow: Option<String>,
}

pub fn parse_auth(cfg: &ServerConfig) -> Result<AuthConfig> {
    match &cfg.auth {
        Some(v) => serde_json::from_value(v.clone()).context("invalid `auth` config"),
        None => Ok(AuthConfig::None),
    }
}

/// Resolve a secret reference: `env:VAR`, `file:/path`, `cmd:<shell command>`
/// (e.g. `cmd:op read op://vault/item/field`), or a literal value.
/// Error messages never include the secret value.
pub async fn resolve_secret(r: &str) -> Result<String> {
    if let Some(var) = r.strip_prefix("env:") {
        return std::env::var(var).map_err(|_| anyhow!("env var {var} is not set"));
    }
    if let Some(path) = r.strip_prefix("file:") {
        let s = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("reading secret file {path}"))?;
        return Ok(s.trim_end_matches(['\n', '\r']).to_string());
    }
    if let Some(cmd) = r.strip_prefix("cmd:") {
        let out = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .context("running secret command")?;
        if !out.status.success() {
            bail!("secret command exited with {}", out.status);
        }
        return Ok(String::from_utf8(out.stdout)?
            .trim_end_matches(['\n', '\r'])
            .to_string());
    }
    Ok(r.to_string())
}

/// Parsed request-time credentials for an HTTP upstream.
#[derive(Default)]
pub struct HttpCreds {
    pub bearer: Option<String>,
    pub headers: HashMap<HeaderName, HeaderValue>,
    pub query: Vec<(String, String)>,
}

fn hv(v: &str) -> Result<HeaderValue> {
    let mut h =
        HeaderValue::from_str(v).map_err(|_| anyhow!("credential is not a valid header value"))?;
    h.set_sensitive(true);
    Ok(h)
}

pub async fn http_creds(cfg: &ServerConfig) -> Result<HttpCreds> {
    let mut c = HttpCreds::default();
    for (k, v) in &cfg.headers {
        let name =
            HeaderName::from_bytes(k.as_bytes()).with_context(|| format!("bad header name {k}"))?;
        c.headers.insert(name, hv(&resolve_secret(v).await?)?);
    }
    match parse_auth(cfg)? {
        AuthConfig::None => {}
        AuthConfig::Bearer { token } => c.bearer = Some(resolve_secret(&token).await?),
        AuthConfig::Basic { username, password } => {
            let raw = format!(
                "{}:{}",
                resolve_secret(&username).await?,
                resolve_secret(&password).await?
            );
            let enc = base64::engine::general_purpose::STANDARD.encode(raw);
            c.headers
                .insert(http::header::AUTHORIZATION, hv(&format!("Basic {enc}"))?);
        }
        AuthConfig::Header { name, value } => {
            let n = HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("bad header name {name}"))?;
            c.headers.insert(n, hv(&resolve_secret(&value).await?)?);
        }
        AuthConfig::Query { name, value } => c.query.push((name, resolve_secret(&value).await?)),
        AuthConfig::Oauth(_) | AuthConfig::ClientCredentials { .. } => {
            bail!("OAuth auth is handled by the oauth module")
        }
        AuthConfig::Unsupported => bail!("unknown auth type"),
    }
    Ok(c)
}

/// Append query credentials to a URL (percent-encoded).
pub fn with_query(url: &str, query: &[(String, String)]) -> String {
    if query.is_empty() {
        return url.to_string();
    }
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    let sep = if url.contains('?') { '&' } else { '?' };
    let q: Vec<String> = query
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect();
    format!("{url}{sep}{}", q.join("&"))
}

/// Resolve secret refs in a stdio server's env.
pub async fn stdio_env(cfg: &ServerConfig) -> Result<Vec<(String, String)>> {
    let mut out = vec![];
    for (k, v) in &cfg.env {
        out.push((
            k.clone(),
            resolve_secret(v)
                .await
                .with_context(|| format!("env {k}"))?,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn server(auth: serde_json::Value) -> ServerConfig {
        ServerConfig {
            url: Some("http://x".into()),
            auth: Some(auth),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn secret_refs() {
        unsafe { std::env::set_var("OMNIX_SECRET_T", "s3") };
        assert_eq!(resolve_secret("env:OMNIX_SECRET_T").await.unwrap(), "s3");
        assert_eq!(resolve_secret("cmd:echo hi").await.unwrap(), "hi");
        assert_eq!(resolve_secret("plain").await.unwrap(), "plain");
        let e = resolve_secret("env:OMNIX_NOPE_X")
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("OMNIX_NOPE_X"));
        assert!(resolve_secret("cmd:exit 3").await.is_err());
    }

    #[tokio::test]
    async fn static_methods() {
        let c = http_creds(&server(json!({"type":"bearer","token":"t0k"})))
            .await
            .unwrap();
        assert_eq!(c.bearer.as_deref(), Some("t0k"));
        let c = http_creds(&server(
            json!({"type":"basic","username":"u","password":"p"}),
        ))
        .await
        .unwrap();
        assert_eq!(c.headers[&http::header::AUTHORIZATION], "Basic dTpw");
        let c = http_creds(&server(
            json!({"type":"header","name":"X-Api-Key","value":"k"}),
        ))
        .await
        .unwrap();
        assert_eq!(c.headers[&HeaderName::from_static("x-api-key")], "k");
        let c = http_creds(&server(
            json!({"type":"query","name":"api key","value":"a&b"}),
        ))
        .await
        .unwrap();
        assert_eq!(
            with_query("http://h/mcp", &c.query),
            "http://h/mcp?api%20key=a%26b"
        );
        assert!(http_creds(&server(json!({"type":"oauth"}))).await.is_err());
    }
}
