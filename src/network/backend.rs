use clap::ValueEnum;

/// libkrun's compatibility feature set for unixstream-backed virtio-net.
pub const COMPAT_NET_FEATURES: u32 = 0;

/// Network backend override for machine launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkBackend {
    /// Use libkrun TSI networking.
    #[value(name = "tsi")]
    Tsi,
    /// Use virtio-net with the host-side smolvm network stack.
    #[serde(alias = "virtio")]
    #[value(name = "virtio-net", alias = "virtio")]
    VirtioNet,
}

impl NetworkBackend {
    /// Stable CLI/storage label for the backend.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tsi => "tsi",
            Self::VirtioNet => "virtio-net",
        }
    }

    /// Human-readable backend label for logs.
    pub const fn log_label(self) -> &'static str {
        match self {
            Self::Tsi => "tsi",
            Self::VirtioNet => "virtio-net",
        }
    }
}

impl std::fmt::Display for NetworkBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkBackend;

    #[test]
    fn virtio_net_serializes_to_canonical_name() {
        let value = serde_json::to_string(&NetworkBackend::VirtioNet).unwrap();
        assert_eq!(value, "\"virtio-net\"");
    }

    #[test]
    fn virtio_net_deserializes_legacy_alias() {
        let value: NetworkBackend = serde_json::from_str("\"virtio\"").unwrap();
        assert_eq!(value, NetworkBackend::VirtioNet);
    }
}
