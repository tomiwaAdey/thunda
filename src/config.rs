// src/config.rs

#[derive(Debug, Clone)]
pub struct Config {
    pub log_level: String,
    pub frame_rx_max_len: usize,
    pub mac_address: String,
    pub ipv6_support: bool,
    pub ipv4_support: bool,
}

impl Config {
    pub fn new() -> Self {
        Config {
            log_level: "info".to_string(),
            frame_rx_max_len: 2048,
            ipv6_support: true,
            ipv4_support: true,
            mac_address: "02:00:00:77:77:77".to_string(),
        }
    }

    pub fn apply(&self) {
        // Implementation to apply the config
    }
}
