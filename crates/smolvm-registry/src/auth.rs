//! OAuth Device Flow client for the smolmachines auth service.
//!
//! Provides [`DeviceFlowClient`] for GitHub OAuth Device Flow (RFC 8628).
//! Token storage is handled by `smolvm::credentials::ConfigFile` — this module
//! only handles the OAuth protocol.

use crate::{RegistryError, Result};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default auth service URL.
pub const DEFAULT_AUTH_URL: &str = "https://auth.smolmachines.com";

/// OAuth client ID for the CLI.
const CLIENT_ID: &str = "smolvm-cli";

/// Response from the device code request.
#[derive(Debug, Deserialize)]
pub struct DeviceCodeResponse {
    /// Device verification code (sent to the token endpoint).
    pub device_code: String,
    /// User-facing code to enter in the browser.
    pub user_code: String,
    /// URL where the user enters the code.
    pub verification_uri: String,
    /// Seconds until the device code expires.
    pub expires_in: u64,
    /// Polling interval in seconds.
    pub interval: u64,
}

/// Response from the token polling endpoint.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    /// JWT access token.
    pub access_token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// GitHub username of the authenticated user.
    pub username: String,
    /// Token lifetime in seconds.
    pub expires_in: Option<u64>,
}

/// Result of polling the token endpoint.
#[derive(Debug)]
pub enum PollResult {
    /// Authorization is still pending — keep polling.
    Pending,
    /// Server requested slower polling — increase interval.
    SlowDown,
    /// Authorization completed — token is available.
    Token(TokenResponse),
    /// Device code expired — user must restart the flow.
    Expired,
}

/// Error response from the auth service.
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
}

/// OAuth Device Flow client for the smolmachines auth service.
pub struct DeviceFlowClient {
    http: reqwest::Client,
    auth_url: String,
}

impl DeviceFlowClient {
    /// Create a new device flow client.
    pub fn new() -> Self {
        let auth_url =
            std::env::var("SMOLVM_AUTH_URL").unwrap_or_else(|_| DEFAULT_AUTH_URL.to_string());
        Self {
            http: reqwest::Client::new(),
            auth_url,
        }
    }

    /// Request a device code from the auth service.
    pub async fn request_device_code(&self) -> Result<DeviceCodeResponse> {
        let url = format!("{}/auth/device", self.auth_url);
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "client_id": CLIENT_ID }))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(RegistryError::AuthError(format!(
                "device code request failed ({}): {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            )));
        }

        Ok(resp.json().await?)
    }

    /// Poll the token endpoint once.
    pub async fn poll_for_token(&self, device_code: &str) -> Result<PollResult> {
        let url = format!("{}/auth/token", self.auth_url);
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({
                "client_id": CLIENT_ID,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            let token: TokenResponse = resp.json().await?;
            return Ok(PollResult::Token(token));
        }

        let body = resp.text().await.unwrap_or_default();
        let error: std::result::Result<ErrorResponse, _> = serde_json::from_str(&body);

        match error {
            Ok(e) => match e.error.as_str() {
                "authorization_pending" => Ok(PollResult::Pending),
                "slow_down" => Ok(PollResult::SlowDown),
                "expired_token" => Ok(PollResult::Expired),
                other => Err(RegistryError::AuthError(format!("auth error: {}", other))),
            },
            Err(_) => Err(RegistryError::AuthError(format!(
                "unexpected auth response: {}",
                body
            ))),
        }
    }

    /// Run the full interactive login flow.
    ///
    /// Requests a device code, opens the browser, polls until authorized.
    pub async fn login_interactive(&self) -> Result<TokenResponse> {
        let device = self.request_device_code().await?;

        println!("Opening browser for GitHub login...");
        println!("  Visit: {}", device.verification_uri);
        println!("  Code:  {}", device.user_code);
        println!();

        if open::that(&device.verification_uri).is_err() {
            println!("Could not open browser automatically.");
            println!("Please visit the URL above and enter the code manually.");
        }

        let mut interval = device.interval;
        let deadline = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + device.expires_in;

        print!("Waiting for authorization...");
        let _ = std::io::Write::flush(&mut std::io::stdout());

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now >= deadline {
                println!(" timed out.");
                return Err(RegistryError::AuthError(
                    "device code expired. Please try again.".to_string(),
                ));
            }

            match self.poll_for_token(&device.device_code).await? {
                PollResult::Pending => {
                    print!(".");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
                PollResult::SlowDown => {
                    interval += 5;
                }
                PollResult::Token(token) => {
                    println!(" done!");
                    return Ok(token);
                }
                PollResult::Expired => {
                    println!(" expired.");
                    return Err(RegistryError::AuthError(
                        "device code expired. Please try again.".to_string(),
                    ));
                }
            }
        }
    }
}
