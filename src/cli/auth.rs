//! Authentication commands for the smolmachines platform.

use clap::{Args, Subcommand};
use smolvm::credentials::{ConfigFile, RegistryCredential};
use smolvm::registry::SMOLMACHINES_REGISTRY;

#[derive(Subcommand, Debug)]
pub enum AuthCmd {
    /// Authenticate with the smolmachines platform
    Login(LoginCmd),
    /// Remove stored credentials
    Logout(LogoutCmd),
    /// Show current authentication status
    Status(StatusCmd),
}

impl AuthCmd {
    pub fn run(self) -> smolvm::Result<()> {
        match self {
            AuthCmd::Login(cmd) => cmd.run(),
            AuthCmd::Logout(cmd) => cmd.run(),
            AuthCmd::Status(cmd) => cmd.run(),
        }
    }
}

#[derive(Args, Debug)]
pub struct LoginCmd {
    /// API token for CI (skip interactive device flow)
    #[arg(long)]
    pub token: Option<String>,

    /// Registry to authenticate with
    #[arg(long, default_value = SMOLMACHINES_REGISTRY)]
    pub registry: String,
}

impl LoginCmd {
    fn run(self) -> smolvm::Result<()> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| smolvm::Error::agent("init tokio runtime", e.to_string()))?;
        rt.block_on(self.run_async())
    }

    async fn run_async(self) -> smolvm::Result<()> {
        let mut config = ConfigFile::load()?;

        if let Some(token) = self.token {
            config.registries.insert(
                self.registry.clone(),
                RegistryCredential {
                    token: Some(token),
                    username: Some("api-key".to_string()),
                    expires_at: None,
                    ..Default::default()
                },
            );
            config.save()?;
            println!("Logged in to {} (API key)", self.registry);
        } else {
            let client = smolvm_registry::DeviceFlowClient::new();
            let response = client
                .login_interactive()
                .await
                .map_err(|e| smolvm::Error::agent("login", e.to_string()))?;

            let expires_at = response.expires_in.map(|secs| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + secs
            });

            config.registries.insert(
                self.registry.clone(),
                RegistryCredential {
                    token: Some(response.access_token),
                    username: Some(response.username.clone()),
                    expires_at,
                    ..Default::default()
                },
            );
            config.save()?;
            println!("Logged in as {}", response.username);
        }

        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct LogoutCmd {
    /// Registry to log out from
    #[arg(long, default_value = SMOLMACHINES_REGISTRY)]
    pub registry: String,
}

impl LogoutCmd {
    fn run(self) -> smolvm::Result<()> {
        let mut config = ConfigFile::load()?;
        config.registries.remove(&self.registry);
        config.save()?;
        println!("Logged out from {}", self.registry);
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct StatusCmd {
    /// Registry to check status for (omit to show all)
    #[arg(long)]
    pub registry: Option<String>,
}

impl StatusCmd {
    fn run(self) -> smolvm::Result<()> {
        let config = ConfigFile::load()?;

        if let Some(registry) = &self.registry {
            // Show specific registry
            show_registry_status(registry, config.registries.get(registry.as_str()));
        } else {
            // Show all
            if config.registries.is_empty() {
                println!("No registries configured");
                println!("  run: smolvm auth login");
                return Ok(());
            }
            for (name, cred) in &config.registries {
                show_registry_status(name, Some(cred));
            }
        }

        Ok(())
    }
}

fn show_registry_status(name: &str, cred: Option<&RegistryCredential>) {
    match cred {
        Some(entry) => {
            if let Some(ref _token) = entry.token {
                if entry.is_expired() {
                    println!("{}: token expired", name);
                    println!("  run: smolvm auth login --registry {}", name);
                } else {
                    let user = entry.username.as_deref().unwrap_or("unknown");
                    print!("{}: logged in as {}", name, user);
                    if let Some(expires_at) = entry.expires_at {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let remaining = expires_at.saturating_sub(now);
                        let hours = remaining / 3600;
                        let minutes = (remaining % 3600) / 60;
                        println!(" (expires in {}h {}m)", hours, minutes);
                    } else {
                        println!(" (API key, never expires)");
                    }
                }
            } else if let Some(ref username) = entry.username {
                let user = username.as_str();
                let source = if let Some(ref env) = entry.password_env {
                    format!("via {}", env)
                } else if entry.password.is_some() {
                    "password configured".to_string()
                } else {
                    "no password".to_string()
                };
                println!("{}: {} ({})", name, user, source);
            }
        }
        None => {
            println!("{}: not configured", name);
        }
    }
}
