use std::sync::atomic::AtomicBool;

use ignore::{WalkBuilder, WalkState};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
struct Settings {
    block_zero_width_spaces: bool,
    block_variation_selectors: bool,
}

fn load_settings() -> Result<Settings, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string("ghost.toml")?;
    let settings = toml::from_str::<Settings>(&content)?;
    Ok(settings)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = load_settings()?;

    let walker = WalkBuilder::new("./").build_parallel();
    let malware_found = AtomicBool::new(false);

    walker.run(|| {
        Box::new(|result| {
            if let Ok(entry) = result {
                // Only process actual files, skip directories
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    if analyze_file(entry.path(), &settings) {
                        malware_found.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
            WalkState::Continue
        })
    });

    if malware_found.load(std::sync::atomic::Ordering::Relaxed) {
        println!("Malware detected in one or more files.");
        std::process::exit(1);
    } else {
        println!("No malware detected.");
    }

    Ok(())
}

fn analyze_file(path: &std::path::Path, settings: &Settings) -> bool {
    if let Ok(content) = std::fs::read_to_string(path) {
        for c in content.chars() {
            let u = c as u32; // Get the raw Unicode hex value

            let is_variation_selector =
                (0xFE00..=0xFE0F).contains(&u) || (0xE0100..=0xE01EF).contains(&u);
            let is_zero_width = (0x200B..=0x200D).contains(&u);

            if (settings.block_variation_selectors && is_variation_selector)
                || (settings.block_zero_width_spaces && is_zero_width)
            {
                println!("Malware found in file: {}", path.display());
                return true; // Malware found
            }
        }
    }
    false // No malware found
}
