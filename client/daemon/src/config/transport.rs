use super::Config;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomaticMtu {
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MtuMode {
    Auto(AutomaticMtu),
    Fixed(FixedMtu),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct FixedMtu(u16);

impl TryFrom<u16> for FixedMtu {
    type Error = &'static str;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if (576..=65503).contains(&value) {
            Ok(Self(value))
        } else {
            Err("fixed MTU must be between 576 and 65503")
        }
    }
}

impl From<FixedMtu> for u16 {
    fn from(value: FixedMtu) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FecMode {
    #[default]
    Auto,
    Off,
    Light,
    Strong,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionMode {
    #[default]
    Auto,
    Off,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayTransportMode {
    #[default]
    AutoUdpFirst,
    TlsOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    pub mtu_mode: MtuMode,
    pub enable_mss_clamping: bool,
    pub fec_mode: FecMode,
    pub compression: CompressionMode,
    pub enable_qos: bool,
    pub max_tx_mbps: Option<NonZeroU32>,
    pub relay_transport: RelayTransportMode,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            mtu_mode: MtuMode::Auto(AutomaticMtu::Auto),
            enable_mss_clamping: true,
            fec_mode: FecMode::default(),
            compression: CompressionMode::default(),
            enable_qos: true,
            max_tx_mbps: None,
            relay_transport: RelayTransportMode::default(),
        }
    }
}

impl Config {
    pub fn tun_mtu(&self) -> u32 {
        match self.transport.mtu_mode {
            MtuMode::Auto(_) => self.network.mtu,
            MtuMode::Fixed(value) => u32::from(value.0),
        }
    }
}
