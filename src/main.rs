mod auth;
mod cache;
mod catalog;
mod commands;
mod config;
mod handles;
mod oauth;
mod policy;
mod pool;
mod sandbox;
#[cfg(test)]
mod sandbox_tests;
mod server;
mod setup;
mod sse;
mod store;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "omnix", about = "MCP code-mode gateway")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List discovered upstream servers
    List,
    /// Authorize an OAuth server (opens a browser, catches the loopback redirect)
    Login {
        server: String,
        /// Print the URL instead of opening a browser
        #[arg(long)]
        no_browser: bool,
        /// Use the device authorization grant (RFC 8628) for headless/SSH machines
        #[arg(long)]
        device: bool,
        /// Extra scope to request (step-up after an insufficient_scope error); repeatable
        #[arg(long = "scope")]
        scopes: Vec<String>,
    },
    /// Check config, credential store and every upstream connection
    Doctor,
    /// Search upstream tools by keyword
    Find {
        query: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Emit TypeScript declarations (.d.ts) for the sandbox globals
    Sdk {
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// Add a server to omnix.json (or the global config with --global)
    Add {
        name: String,
        #[arg(long)]
        command: Option<String>,
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
        /// KEY=VALUE for stdio servers (use env:/cmd: secret references for secrets)
        #[arg(long)]
        env: Vec<String>,
        #[arg(long)]
        url: Option<String>,
        /// "http" (default) or "sse"
        #[arg(long)]
        transport: Option<String>,
        /// Bearer token secret reference (env:VAR, file:PATH, cmd:...)
        #[arg(long)]
        bearer: Option<String>,
        /// Use OAuth (then run `omnix login <name>`)
        #[arg(long)]
        oauth: bool,
        #[arg(long)]
        global: bool,
    },
    /// Remove a server from omnix.json (or the global config with --global)
    Remove {
        name: String,
        #[arg(long)]
        global: bool,
    },
    /// Point coding agents at the gateway (shows a diff and asks before editing anything)
    Setup {
        /// Limit to these agents (see --list); repeatable
        #[arg(long = "agent")]
        agents: Vec<String>,
        /// Print what would change without writing
        #[arg(long)]
        dry_run: bool,
        /// Don't prompt (for scripts)
        #[arg(long, short = 'y')]
        yes: bool,
        /// Add the omnix entry but leave the agent's existing servers in place
        #[arg(long)]
        keep_existing: bool,
        /// Undo a previous setup: restore moved servers and remove the omnix entry
        #[arg(long)]
        remove: bool,
        /// Show detected agent config files and exit
        #[arg(long)]
        list: bool,
    },
    /// Forget stored credentials for a server
    Logout { server: String },
    /// Run the gateway as an MCP server on stdio
    Serve,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::List => {
            let (cfg, sources) = config::load(&std::env::current_dir()?)?;
            for s in sources {
                eprintln!("source: {s}");
            }
            for (name, s) in cfg.servers {
                let kind = if s.is_stdio() {
                    "stdio"
                } else {
                    s.transport.as_deref().unwrap_or("http")
                };
                println!("{name}\t{kind}");
            }
        }
        Cmd::Login {
            server,
            no_browser,
            device,
            scopes,
        } => {
            let (cfg, _) = config::load(&std::env::current_dir()?)?;
            let sc = cfg
                .servers
                .get(&server)
                .ok_or_else(|| anyhow::anyhow!("unknown server `{server}`"))?;
            oauth::login(&server, sc, !no_browser, device, &scopes).await?;
        }
        Cmd::Logout { server } => {
            let (cfg, _) = config::load(&std::env::current_dir()?)?;
            let sc = cfg
                .servers
                .get(&server)
                .ok_or_else(|| anyhow::anyhow!("unknown server `{server}`"))?;
            oauth::logout(&server, sc).await?;
            eprintln!("Logged out of `{server}`.");
        }
        Cmd::Doctor => commands::doctor().await?,
        Cmd::Find { query, limit } => commands::find(&query, limit).await?,
        Cmd::Sdk { out } => commands::sdk(out).await?,
        Cmd::Add {
            name,
            command,
            args,
            env,
            url,
            transport,
            bearer,
            oauth,
            global,
        } => commands::add(commands::AddArgs {
            name,
            command,
            args,
            env,
            url,
            transport,
            bearer,
            oauth,
            global,
        })?,
        Cmd::Remove { name, global } => commands::remove(&name, global)?,
        Cmd::Setup {
            agents,
            dry_run,
            yes,
            keep_existing,
            remove,
            list,
        } => {
            let env = setup::Env {
                home: dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home directory"))?,
                cwd: std::env::current_dir()?,
            };
            if list {
                setup::list(&env);
            } else {
                let o = setup::Opts {
                    agents,
                    yes,
                    dry_run,
                    keep_existing,
                    env,
                };
                if remove {
                    setup::remove(&o)?
                } else {
                    setup::setup(&o)?
                }
            }
        }
        Cmd::Serve => {
            use rmcp::{ServiceExt, transport::stdio};
            let (cfg, _) = config::load(&std::env::current_dir()?)?;
            // Handshake with the agent right away; upstreams connect in the background.
            let gw = server::Gateway::lazy(cfg, sandbox::Limits::default());
            let svc = gw.serve(stdio()).await?;
            svc.waiting().await?;
        }
    }
    Ok(())
}
