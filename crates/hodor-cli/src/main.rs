//! `hodor`: the single user-facing binary. Subcommand dispatch only —
//! business logic lives in `cmds/*` and the library crates.

mod cmds;
mod config;
mod i18n;

use clap::{Parser, Subcommand};
use hodor_core::object::ObjectKind;

#[derive(Parser)]
// Clap help stays English until M6 wires Fluent into clap; all runtime
// output goes through the message catalogs (see i18n.rs).
#[command(
    name = "hodor",
    version,
    about = "Hodor — hold the door between your AI agent and your secrets."
)]
struct Cli {
    /// UI language override: en | zh
    #[arg(long, global = true)]
    lang: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the vault: set master passphrase and anti-phishing phrase
    Init,
    /// Test-unlock the vault once (one-shot: key wipes at process exit)
    Unlock,
    /// Explain lock semantics (daemon-level locking arrives in M2)
    Lock,
    /// Vault presence and config summary; never prompts
    Status,
    /// Store a secret (value is prompted out-of-band, never via argv)
    Add {
        #[command(subcommand)]
        kind: AddKind,
    },
    /// List objects (aliases and policies only, never values)
    List,
    /// Remove an object
    Revoke { alias: String },
    /// Adjust an object's policy
    Policy {
        alias: String,
        #[arg(long)]
        confirm: Option<String>,
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        max_uses: Option<u64>,
        #[arg(long)]
        agents: Option<String>,
        #[arg(long)]
        uses: Option<String>,
    },
    /// Show the audit log tail, or verify the hash chain
    Audit {
        #[arg(long)]
        verify: bool,
    },
    /// Manage plain-text preferences (config.toml)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Execute a command with {{alias}} substitution (manual, human-run)
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum AddKind {
    /// Store the sudo password (alias: sudo)
    Sudo,
    /// Store an SSH credential under an alias
    Ssh { alias: String },
    /// Store an API key under an alias
    #[command(name = "api-key")]
    ApiKey { alias: String },
    /// Store a token under an alias
    Token { alias: String },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Set a config value
    Set { key: String, value: String },
    /// Print a config value
    Get { key: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cfg = config::load()?;
    let msgs = i18n::Msgs::load(i18n::resolve(cli.lang.as_deref(), &cfg));
    let session = format!("cli:{}", std::process::id());
    match cli.command {
        Command::Init => cmds::init::run(&msgs, &cfg, &session),
        Command::Unlock => cmds::unlock::run(&msgs, &cfg, &session),
        Command::Lock => cmds::lock::run(&msgs),
        Command::Status => cmds::status::run(&msgs, &cfg),
        Command::Add { kind } => add_dispatch(&msgs, &cfg, &session, kind),
        Command::List => cmds::list::run(&msgs, &cfg),
        Command::Revoke { alias } => cmds::revoke::run(&msgs, &cfg, &session, &alias),
        Command::Policy {
            alias,
            confirm,
            ttl,
            max_uses,
            agents,
            uses,
        } => cmds::policy::run(
            &msgs,
            &cfg,
            &session,
            &alias,
            cmds::policy::PolicyChange {
                confirm,
                ttl,
                max_uses,
                agents,
                uses,
            },
        ),
        Command::Audit { verify } => cmds::audit::run(&msgs, &cfg, verify),
        Command::Config { action } => match action {
            ConfigAction::Set { key, value } => cmds::config_cmd::set(&msgs, &key, &value),
            ConfigAction::Get { key } => cmds::config_cmd::get(&key),
        },
        Command::Run { args } => cmds::run::run(&msgs, &cfg, &session, &args),
    }
}

fn add_dispatch(
    msgs: &i18n::Msgs,
    cfg: &config::Config,
    session: &str,
    kind: AddKind,
) -> anyhow::Result<()> {
    let (alias, object_kind) = match kind {
        AddKind::Sudo => ("sudo".to_string(), ObjectKind::Sudo),
        AddKind::Ssh { alias } => (alias, ObjectKind::Ssh),
        AddKind::ApiKey { alias } => (alias, ObjectKind::ApiKey),
        AddKind::Token { alias } => (alias, ObjectKind::Token),
    };
    cmds::add::run(msgs, cfg, session, &alias, object_kind)
}
