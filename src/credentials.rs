//! Unified credential and configuration store.
//!
//! All smolvm configuration lives in a single file: `~/.config/smolvm/config.toml`.
//! This includes machine defaults, registry credentials (JWT tokens and
//! username/password), and mirrors.
//!
//! ```toml
//! [defaults]
//! cpus = 4
//! memory = 8192
//!
//! [registries."registry.smolmachines.com"]
//! token = "eyJ..."
//! username = "binsquare"
//! expires_at = 1748736000
//!
//! [registries."docker.io"]
//! username = "myuser"
//! password_env = "DOCKER_HUB_TOKEN"
//! ```

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// The unified smolvm configuration file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConfigFile {
    /// Machine defaults.
    #[serde(default)]
    pub defaults: Defaults,

    /// Per-registry credentials and settings.
    #[serde(default)]
    pub registries: HashMap<String, RegistryCredential>,
}

/// Machine defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Defaults {
    /// Default vCPU count for new machines.
    pub cpus: Option<u32>,
    /// Default memory in MiB for new machines.
    pub memory: Option<u32>,
    /// Default DNS server.
    pub dns: Option<String>,
}

/// Credentials and settings for a single registry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryCredential {
    /// JWT or API key (from `smolvm auth login`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Username (for both JWT identity and basic auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Token expiry as Unix timestamp. None = never expires (API keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Password (plaintext — not recommended, use password_env).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Environment variable containing the password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,

    /// Mirror URL for pull-through caching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<String>,
}

// ClientAuth is re-exported for use in resolve() return type.
pub use smolvm_registry::ClientAuth;

impl RegistryCredential {
    /// Check if the token has expired.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires_at) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                now >= expires_at
            }
            None => false,
        }
    }

    /// Resolve the password from either `password` or `password_env`.
    pub fn resolve_password(&self) -> Option<String> {
        self.password_env
            .as_ref()
            .and_then(|env| std::env::var(env).ok())
            .or_else(|| self.password.clone())
    }
}

impl ConfigFile {
    /// Load config from `~/.config/smolvm/config.toml`.
    /// Returns empty config if the file doesn't exist.
    /// Migrates from old `auth.json` and `registries.toml` if they exist.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;

        let mut config = if path.exists() {
            let data = std::fs::read_to_string(&path)
                .map_err(|e| Error::config(format!("read {}", path.display()), e.to_string()))?;
            toml::from_str(&data)
                .map_err(|e| Error::config(format!("parse {}", path.display()), e.to_string()))?
        } else {
            Self::default()
        };

        // Migrate from old files if they exist.
        let migrated = config.migrate_old_files()?;
        if migrated {
            config.save()?;
        }

        Ok(config)
    }

    /// Save config atomically (temp file + rename). File mode 0600.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::config(format!("create dir {}", parent.display()), e.to_string())
            })?;
        }

        let toml = toml::to_string_pretty(self)
            .map_err(|e| Error::config("serialize config", e.to_string()))?;

        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &toml)
            .map_err(|e| Error::config(format!("write {}", tmp.display()), e.to_string()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&tmp, perms)
                .map_err(|e| Error::config("set permissions", e.to_string()))?;
        }

        std::fs::rename(&tmp, &path)
            .map_err(|e| Error::config("rename config file", e.to_string()))?;

        Ok(())
    }

    /// Path to the config file.
    pub fn path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| Error::config("resolve path", "no config directory found"))?;
        Ok(config_dir.join("smolvm").join("config.toml"))
    }

    /// Resolve credentials for a registry.
    ///
    /// Priority: Bearer token (if not expired) > Basic auth > None.
    pub fn resolve(&self, registry: &str) -> Option<ClientAuth> {
        let entry = self.registries.get(registry)?;

        // JWT/API key takes priority.
        if let Some(ref token) = entry.token {
            if !entry.is_expired() {
                return Some(ClientAuth::Bearer(token.clone()));
            }
        }

        // Basic auth fallback.
        if let Some(ref username) = entry.username {
            if let Some(password) = entry.resolve_password() {
                return Some(ClientAuth::Basic(username.clone(), password));
            }
        }

        None
    }

    /// Get mirror URL for a registry.
    pub fn get_mirror(&self, registry: &str) -> Option<&str> {
        self.registries.get(registry)?.mirror.as_deref()
    }

    /// Get credentials for OCI image pulls (used by the agent).
    ///
    /// Returns `RegistryAuth` (username + password) for registries that have
    /// basic auth configured. For token-only registries (JWT from `smolvm auth login`),
    /// returns the username "token" with the JWT as password — this works because
    /// OCI registries accept Bearer tokens via basic auth with any username.
    pub fn get_registry_auth(&self, registry: &str) -> Option<smolvm_protocol::RegistryAuth> {
        let entry = self.registries.get(registry)?;

        // Prefer token auth (JWT/API key).
        if let Some(ref token) = entry.token {
            if !entry.is_expired() {
                return Some(smolvm_protocol::RegistryAuth {
                    username: "token".to_string(),
                    password: token.clone(),
                });
            }
        }

        // Fall back to username/password.
        let username = entry.username.as_ref()?;
        let password = entry.resolve_password()?;
        Some(smolvm_protocol::RegistryAuth {
            username: username.clone(),
            password,
        })
    }

    /// Migrate from old `auth.json` and `registries.toml` if they exist.
    /// Returns true if any migration occurred.
    fn migrate_old_files(&mut self) -> Result<bool> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| Error::config("resolve path", "no config directory found"))?;
        let smolvm_dir = config_dir.join("smolvm");
        let mut migrated = false;

        // Migrate auth.json
        let auth_path = smolvm_dir.join("auth.json");
        if auth_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&auth_path) {
                if let Ok(auth_map) =
                    serde_json::from_str::<HashMap<String, serde_json::Value>>(&data)
                {
                    for (registry, value) in auth_map {
                        if !self.registries.contains_key(&registry) {
                            let mut cred = RegistryCredential::default();
                            if let Some(t) = value.get("token").and_then(|v| v.as_str()) {
                                cred.token = Some(t.to_string());
                            }
                            if let Some(u) = value.get("username").and_then(|v| v.as_str()) {
                                cred.username = Some(u.to_string());
                            }
                            if let Some(e) = value.get("expires_at").and_then(|v| v.as_u64()) {
                                cred.expires_at = Some(e);
                            }
                            self.registries.insert(registry, cred);
                        }
                    }
                    let _ = std::fs::remove_file(&auth_path);
                    migrated = true;
                    tracing::info!("migrated credentials from auth.json to config.toml");
                }
            }
        }

        // Migrate registries.toml
        let reg_path = smolvm_dir.join("registries.toml");
        if reg_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&reg_path) {
                if let Ok(old_config) = toml::from_str::<OldRegistryConfig>(&data) {
                    for (registry, entry) in old_config.registries {
                        if !self.registries.contains_key(&registry) {
                            self.registries.insert(
                                registry,
                                RegistryCredential {
                                    username: entry.username,
                                    password: entry.password,
                                    password_env: entry.password_env,
                                    mirror: entry.mirror,
                                    ..Default::default()
                                },
                            );
                        }
                    }
                    let _ = std::fs::remove_file(&reg_path);
                    migrated = true;
                    tracing::info!("migrated credentials from registries.toml to config.toml");
                }
            }
        }

        Ok(migrated)
    }
}

/// Old registries.toml format (for migration only).
#[derive(Deserialize)]
struct OldRegistryConfig {
    #[serde(default)]
    registries: HashMap<String, OldRegistryEntry>,
}

#[derive(Deserialize)]
struct OldRegistryEntry {
    username: Option<String>,
    password: Option<String>,
    password_env: Option<String>,
    mirror: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_roundtrip() {
        let mut config = ConfigFile::default();
        config.defaults.cpus = Some(4);
        config.defaults.memory = Some(8192);

        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86400;

        config.registries.insert(
            "registry.smolmachines.com".to_string(),
            RegistryCredential {
                token: Some("eyJ...".to_string()),
                username: Some("binsquare".to_string()),
                expires_at: Some(future),
                ..Default::default()
            },
        );

        config.registries.insert(
            "docker.io".to_string(),
            RegistryCredential {
                username: Some("myuser".to_string()),
                password_env: Some("DOCKER_TOKEN".to_string()),
                ..Default::default()
            },
        );

        let toml = toml::to_string_pretty(&config).unwrap();
        let restored: ConfigFile = toml::from_str(&toml).unwrap();

        assert_eq!(restored.defaults.cpus, Some(4));
        assert_eq!(restored.registries.len(), 2);
        assert!(restored
            .registries
            .get("registry.smolmachines.com")
            .unwrap()
            .token
            .is_some());
    }

    #[test]
    fn test_resolve_bearer() {
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86400;

        let mut config = ConfigFile::default();
        config.registries.insert(
            "example.com".to_string(),
            RegistryCredential {
                token: Some("jwt-token".to_string()),
                username: Some("user".to_string()),
                expires_at: Some(future),
                password: Some("pass".to_string()),
                ..Default::default()
            },
        );

        // Token takes priority over basic auth.
        match config.resolve("example.com") {
            Some(ClientAuth::Bearer(t)) => assert_eq!(t, "jwt-token"),
            other => panic!("expected Bearer, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_basic_when_token_expired() {
        let mut config = ConfigFile::default();
        config.registries.insert(
            "example.com".to_string(),
            RegistryCredential {
                token: Some("expired-jwt".to_string()),
                username: Some("user".to_string()),
                expires_at: Some(0), // expired
                password: Some("pass".to_string()),
                ..Default::default()
            },
        );

        // Expired token falls back to basic auth.
        match config.resolve("example.com") {
            Some(ClientAuth::Basic(u, p)) => {
                assert_eq!(u, "user");
                assert_eq!(p, "pass");
            }
            other => panic!("expected Basic, got {:?}", other),
        }
    }

    #[test]
    fn test_resolve_none_for_missing() {
        let config = ConfigFile::default();
        assert!(config.resolve("nonexistent.com").is_none());
    }

    #[test]
    fn test_resolve_password_env() {
        std::env::set_var("SMOLVM_TEST_CRED_PW", "env-password");

        let mut config = ConfigFile::default();
        config.registries.insert(
            "example.com".to_string(),
            RegistryCredential {
                username: Some("user".to_string()),
                password_env: Some("SMOLVM_TEST_CRED_PW".to_string()),
                ..Default::default()
            },
        );

        match config.resolve("example.com") {
            Some(ClientAuth::Basic(u, p)) => {
                assert_eq!(u, "user");
                assert_eq!(p, "env-password");
            }
            other => panic!("expected Basic, got {:?}", other),
        }

        std::env::remove_var("SMOLVM_TEST_CRED_PW");
    }

    #[test]
    fn test_api_key_never_expires() {
        let mut config = ConfigFile::default();
        config.registries.insert(
            "example.com".to_string(),
            RegistryCredential {
                token: Some("api-key".to_string()),
                username: Some("ci".to_string()),
                expires_at: None, // API key, no expiry
                ..Default::default()
            },
        );

        match config.resolve("example.com") {
            Some(ClientAuth::Bearer(t)) => assert_eq!(t, "api-key"),
            other => panic!("expected Bearer, got {:?}", other),
        }
    }
}
