use std::path::Path;

use serde::Deserialize;

#[derive(Default, Deserialize)]
pub struct Settings {
    pub exclude: Vec<String>,
    pub unicode: UnicodeSettings,
}

impl Settings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(config: &Path) -> Result<Self, ()> {
        let content = std::fs::read_to_string(config).unwrap();
        let settings = toml::from_str::<Settings>(&content).unwrap();
        Ok(settings)
    }
}

#[derive(Default, Deserialize)]
pub struct UnicodeSettings {
    pub check_zero_width: bool,
    pub check_variation_selectors: bool,
    pub check_bidi_controls: bool,
    pub check_invisible_math: bool,
    pub check_homoglyphs: bool,

    pub allowlist: UnicodeAllowlist,
}

#[derive(Default, Deserialize)]
pub struct UnicodeAllowlist {
    pub files: Vec<String>,
    pub chars: Vec<String>,
}
