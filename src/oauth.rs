//! OAuth for HTTP upstreams, built on rmcp's `auth` module (PRM/AS discovery, PKCE S256,
//! resource indicators, pre-registered / CIMD / DCR client registration, refresh with
//! rotation, 401 retry, scope step-up). This module adds: the interactive loopback login,
//! credential persistence (`store.rs`) and the non-interactive connect used by `serve`.

use crate::auth::{AuthConfig, OauthConfig, parse_auth, resolve_secret};
use crate::config::ServerConfig;
use crate::store::OmnixStore;
use anyhow::{Context, Result, anyhow, bail};
use oauth2::TokenResponse as _;
use rmcp::transport::auth::{CredentialStore, StoredCredentials};
use rmcp::transport::{
    StreamableHttpClientTransport,
    auth::{
        AuthClient, AuthorizationManager, AuthorizationRequest, ClientCredentialsConfig,
        JwtSigningAlgorithm, OAuthState,
    },
    streamable_http_client::StreamableHttpClientTransportConfig,
};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

fn is_local(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            u.host_str()
                .map(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]")
        })
        .unwrap_or(false)
}

async fn manager(name: &str, url: &str, persist: bool) -> Result<AuthorizationManager> {
    let mut m = if is_local(url) {
        // The user pointed us at a loopback MCP server; don't block its own metadata.
        AuthorizationManager::new_allowing_private_addresses(url).await
    } else {
        AuthorizationManager::new(url).await
    }
    .map_err(|e| anyhow!("oauth init: {e}"))?;
    if persist {
        m.set_credential_store(OmnixStore::new(name, url));
    }
    Ok(m)
}

fn oauth_cfg(cfg: &ServerConfig) -> Result<OauthConfig> {
    match parse_auth(cfg)? {
        AuthConfig::Oauth(o) => Ok(o),
        _ => bail!("server is not configured with auth.type = \"oauth\""),
    }
}

/// Non-interactive: build a transport using stored credentials. Never opens a browser.
pub async fn connect_transport(
    name: &str,
    cfg: &ServerConfig,
    tc: StreamableHttpClientTransportConfig,
) -> Result<StreamableHttpClientTransport<AuthClient<reqwest::Client>>> {
    let url = cfg.url.as_deref().context("oauth requires `url`")?;
    let mut m = manager(name, url, true).await?;
    let ok = m
        .initialize_from_store()
        .await
        .map_err(|e| anyhow!("loading credentials: {e}"))?;
    if !ok {
        bail!("not logged in: run `omnix login {name}`");
    }
    Ok(StreamableHttpClientTransport::with_client(
        AuthClient::new(reqwest::Client::new(), m),
        tc,
    ))
}

/// Machine-to-machine: exchange client credentials at connect time (no browser, no login).
/// Tokens live in memory only. A background task re-exchanges before expiry, so long
/// sessions keep working (client-credentials grants have no refresh token).
pub async fn connect_client_credentials(
    name: &str,
    cfg: &ServerConfig,
    tc: StreamableHttpClientTransportConfig,
) -> Result<StreamableHttpClientTransport<AuthClient<reqwest::Client>>> {
    let url = cfg
        .url
        .as_deref()
        .context("client_credentials requires `url`")?;
    let AuthConfig::ClientCredentials {
        client_id,
        client_secret,
        private_key,
        algorithm,
        scopes,
    } = parse_auth(cfg)?
    else {
        bail!("server is not configured with auth.type = \"client_credentials\"");
    };
    let client_id = resolve_secret(&client_id).await?;
    // The MCP spec requires `resource` in token requests: canonical URI, no trailing slash.
    let resource = Some(url.trim_end_matches('/').to_string());
    let cc = match (client_secret, private_key) {
        (Some(sec), None) => ClientCredentialsConfig::ClientSecret {
            client_id,
            client_secret: resolve_secret(&sec).await?,
            scopes,
            resource,
        },
        (None, Some(pk)) => ClientCredentialsConfig::PrivateKeyJwt {
            client_id,
            signing_key: resolve_secret(&pk).await?.into_bytes(),
            signing_algorithm: parse_alg(algorithm.as_deref())?,
            token_endpoint_audience: None,
            scopes,
            resource,
        },
        _ => bail!("client_credentials needs exactly one of `client_secret` or `private_key`"),
    };
    let mut m = manager(name, url, false).await?;
    let meta = m
        .resolve_metadata()
        .await
        .map_err(|e| anyhow!("discovery for `{name}`: {e}"))?
        .metadata;
    m.set_metadata(meta);
    m.validate_client_credentials_metadata(&cc)
        .map_err(|e| anyhow!("`{name}`: {e}"))?;
    m.configure_client_credentials(&cc)
        .map_err(|e| anyhow!("`{name}`: {e}"))?;
    let client = AuthClient::new(reqwest::Client::new(), m);
    let first = exchange_off_thread(client.auth_manager.clone(), cc.clone())
        .await
        .map_err(|e| anyhow!("client credentials for `{name}`: {e}"))?;
    spawn_reexchange(name.to_string(), client.auth_manager.clone(), cc, first);
    Ok(StreamableHttpClientTransport::with_client(client, tc))
}

fn parse_alg(a: Option<&str>) -> Result<JwtSigningAlgorithm> {
    Ok(match a.unwrap_or("RS256") {
        "RS256" => JwtSigningAlgorithm::RS256,
        "RS384" => JwtSigningAlgorithm::RS384,
        "RS512" => JwtSigningAlgorithm::RS512,
        "ES256" => JwtSigningAlgorithm::ES256,
        "ES384" => JwtSigningAlgorithm::ES384,
        other => bail!("unsupported signing algorithm `{other}`"),
    })
}

type SharedManager = std::sync::Arc<tokio::sync::Mutex<AuthorizationManager>>;

/// rmcp's JWT client-credentials future is not `Send`; run it on a blocking thread so the
/// rest of the (spawned, `Send`) connect path stays valid. Returns the token lifetime.
async fn exchange_off_thread(
    mgr: SharedManager,
    cc: ClientCredentialsConfig,
) -> Result<Option<Duration>> {
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        handle.block_on(async move {
            mgr.lock()
                .await
                .exchange_client_credentials(&cc)
                .await
                .map(|r| r.expires_in())
                .map_err(|e| anyhow!("{e}"))
        })
    })
    .await?
}

/// Re-exchange at 80% of the token lifetime (min 30s); retry every 30s on failure.
fn spawn_reexchange(
    name: String,
    mgr: SharedManager,
    cc: ClientCredentialsConfig,
    first_expiry: Option<Duration>,
) {
    let wait_for = |e: Option<Duration>| {
        e.map(|d| d.mul_f64(0.8))
            .unwrap_or(Duration::from_secs(3000))
            .max(Duration::from_secs(30))
    };
    tokio::spawn(async move {
        let mut wait = wait_for(first_expiry);
        loop {
            tokio::time::sleep(wait).await;
            wait = match exchange_off_thread(mgr.clone(), cc.clone()).await {
                Ok(e) => wait_for(e),
                Err(e) => {
                    eprintln!("omnix: re-exchanging client credentials for `{name}` failed: {e}");
                    Duration::from_secs(30)
                }
            };
        }
    });
}

/// Probe the server unauthenticated and return its `WWW-Authenticate` challenge, if any.
async fn probe_challenge(url: &str) -> Option<String> {
    let r = reqwest::Client::new()
        .post(url)
        .header("accept", "application/json, text/event-stream")
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"omnix","version":"0"}}}))
        .timeout(Duration::from_secs(15))
        .send()
        .await
        .ok()?;
    (r.status() == 401)
        .then(|| {
            r.headers()
                .get("www-authenticate")?
                .to_str()
                .ok()
                .map(str::to_string)
        })
        .flatten()
}

fn open_browser(url: &str) {
    let (cmd, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
        ("open", vec![url])
    } else if cfg!(target_os = "windows") {
        ("cmd", vec!["/C", "start", "", url])
    } else {
        ("xdg-open", vec![url])
    };
    let _ = std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Wait for the redirect on the loopback listener; returns the request path+query.
async fn await_callback(l: TcpListener) -> Result<String> {
    loop {
        let (mut sock, _) = l.accept().await?;
        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).await?;
        let req = String::from_utf8_lossy(&buf[..n]);
        let path = req
            .lines()
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .unwrap_or("")
            .to_string();
        let ok = path.starts_with("/callback");
        let (status, body) = if ok {
            (
                "200 OK",
                "<h3>omnix: login complete. You can close this tab.</h3>",
            )
        } else {
            ("404 Not Found", "not found")
        };
        let _ = sock
            .write_all(
                format!("HTTP/1.1 {status}\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len())
                    .as_bytes(),
            )
            .await;
        if ok {
            return Ok(path);
        }
    }
}

/// Interactive login: discovery -> registration -> browser -> loopback callback -> token store.
pub async fn login(
    name: &str,
    cfg: &ServerConfig,
    open: bool,
    device: bool,
    extra_scopes: &[String],
) -> Result<()> {
    let url = cfg.url.as_deref().context("oauth requires `url`")?;
    let mut o = oauth_cfg(cfg)?;
    if !extra_scopes.is_empty() {
        // Scope step-up: request the union of what was granted before and what is now needed.
        if let Ok(Some(prev)) = OmnixStore::new(name, url).load().await {
            for s in prev.granted_scopes {
                if !o.scopes.contains(&s) {
                    o.scopes.push(s);
                }
            }
        }
        for s in extra_scopes {
            if !o.scopes.contains(s) {
                o.scopes.push(s.clone());
            }
        }
    }
    if device || o.flow.as_deref() == Some("device") {
        return login_device(name, url, &o).await;
    }
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let mut req = AuthorizationRequest::new(&redirect)
        .with_client_name(o.client_name.as_deref().unwrap_or("omnix"))
        .with_application_type("native");
    if !o.scopes.is_empty() {
        req = req.with_scopes(o.scopes.clone());
    }
    if let Some(id) = &o.client_id {
        req = req.with_preregistered_client(id);
        if let Some(sec) = &o.client_secret {
            req = req.with_client_secret(resolve_secret(sec).await?);
        }
    }
    if let Some(u) = &o.client_metadata_url {
        req = req.with_client_metadata_url(u);
    }
    if let Some(ch) = probe_challenge(url).await {
        req = req.with_challenge(ch);
    }

    let mut state = OAuthState::Unauthorized(manager(name, url, true).await?);
    state
        .start_authorization(req)
        .await
        .map_err(|e| anyhow!("authorization setup: {e}"))?;
    let auth_url = state
        .get_authorization_url()
        .await
        .map_err(|e| anyhow!("{e}"))?;
    eprintln!("Open this URL to authorize `{name}`:\n\n  {auth_url}\n");
    if open {
        open_browser(&auth_url);
    }
    let path = tokio::time::timeout(LOGIN_TIMEOUT, await_callback(listener))
        .await
        .map_err(|_| anyhow!("login timed out after {}s", LOGIN_TIMEOUT.as_secs()))??;
    state
        .handle_callback_url(&format!("http://127.0.0.1:{port}{path}"))
        .await
        .map_err(|e| anyhow!("token exchange: {e}"))?;
    eprintln!("Logged in to `{name}`.");
    Ok(())
}

/// Forget stored credentials for a server.
pub async fn logout(name: &str, cfg: &ServerConfig) -> Result<()> {
    use rmcp::transport::auth::CredentialStore;
    let url = cfg.url.as_deref().context("oauth requires `url`")?;
    OmnixStore::new(name, url)
        .clear()
        .await
        .map_err(|e| anyhow!("{e}"))
}

/// RFC 8628 device authorization grant. NOT part of the MCP authorization spec: used only
/// when the authorization server advertises `device_authorization_endpoint` and the config
/// supplies a pre-registered public `client_id`. For headless / SSH machines.
async fn login_device(name: &str, url: &str, o: &OauthConfig) -> Result<()> {
    use serde_json::Value;
    let client_id = o
        .client_id
        .clone()
        .context("device flow needs auth.client_id (pre-registered client)")?;
    let m = manager(name, url, true).await?;
    let challenge = probe_challenge(url).await;
    let meta = m
        .resolve_metadata_from_challenge(challenge.as_deref())
        .await
        .map_err(|e| anyhow!("discovery: {e}"))?
        .metadata;
    let dev_ep = meta
        .additional_fields
        .get("device_authorization_endpoint")
        .and_then(|v| v.as_str())
        .context("authorization server does not advertise device_authorization_endpoint (device flow is not part of the MCP spec)")?
        .to_string();
    let http = reqwest::Client::new();
    let resource = url.trim_end_matches('/').to_string();
    let mut form = vec![
        ("client_id", client_id.clone()),
        ("resource", resource.clone()),
    ];
    if !o.scopes.is_empty() {
        form.push(("scope", o.scopes.join(" ")));
    }
    let dev: Value = http
        .post(&dev_ep)
        .form(&form)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let s = |k: &str| dev.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let device_code = s("device_code").context("no device_code in response")?;
    let uri = s("verification_uri_complete")
        .or_else(|| s("verification_uri"))
        .context("no verification_uri")?;
    eprintln!("To authorize `{name}`, visit:\n\n  {uri}\n");
    if let Some(c) = s("user_code") {
        eprintln!("and enter code: {c}\n");
    }
    let mut interval = dev.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);
    let expires = dev
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(600)
        .min(1800);
    let deadline = std::time::Instant::now() + Duration::from_secs(expires);
    let tok: Value = loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        if std::time::Instant::now() > deadline {
            bail!("device code expired; run login again");
        }
        let r = http
            .post(&meta.token_endpoint)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", &device_code),
                ("client_id", &client_id),
                ("resource", &resource),
            ])
            .send()
            .await?;
        let ok = r.status().is_success();
        let body: Value = r.json().await.unwrap_or(Value::Null);
        if ok {
            break body;
        }
        match body.get("error").and_then(|e| e.as_str()) {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            Some("access_denied") => bail!("authorization was denied"),
            Some("expired_token") => bail!("device code expired; run login again"),
            Some(e) => bail!("token endpoint error: {e}"),
            None => bail!("unexpected token endpoint response"),
        }
    };
    let token =
        serde_json::from_value(tok.clone()).map_err(|e| anyhow!("bad token response: {e}"))?;
    let scopes = tok
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s.split(' ').map(String::from).collect())
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let creds = StoredCredentials::new(client_id, Some(token), scopes, Some(now))
        .with_issuer(meta.issuer.clone());
    OmnixStore::new(name, url)
        .save(creds)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    eprintln!("Logged in to `{name}` (device flow).");
    Ok(())
}
