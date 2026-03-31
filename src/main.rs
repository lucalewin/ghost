mod settings;

use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};

use ignore::{WalkBuilder, WalkState};

use crate::settings::Settings;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = PathBuf::from("./ghost.toml");
    let settings = Settings::load(&config_path).unwrap_or_else(|_| {
        println!("Notice: ghost.toml not found, using default security settings.");
        Settings::default()
    });

    let check_vs = settings.unicode.check_variation_selectors;
    let check_zw = settings.unicode.check_zero_width;
    let check_bidi = settings.unicode.check_bidi_controls;

    // If all checks are disabled, don't even bother scanning!
    if !check_vs && !check_zw && !check_bidi {
        return Ok(());
    }

    let walker = WalkBuilder::new("./").build_parallel();

    let files_scanned = AtomicUsize::new(0);
    let malware_found = AtomicUsize::new(0);
    let start_time = Instant::now();

    walker.run(|| {
        Box::new(|result| {
            if let Ok(entry) = result {
                // Only process actual files, skip directories
                if entry.file_type().map_or(false, |ft| ft.is_file()) {
                    files_scanned.fetch_add(1, Ordering::Relaxed);

                    let found_count = analyze_file(entry.path(), &settings);
                    if found_count > 0 {
                        malware_found.fetch_add(found_count, Ordering::Relaxed);
                    }
                }
            }
            WalkState::Continue
        })
    });

    let duration = start_time.elapsed();
    let total_scanned = files_scanned.load(Ordering::Relaxed);
    let total_found = malware_found.load(Ordering::Relaxed);

    println!("\n-------------------------------------------");
    println!("    Ghost Scan Complete in {:.2?}", duration);
    println!("    Files scanned: {}", total_scanned);

    if total_found > 0 {
        println!("    Malicious lines found: {}", total_found);
        println!("-------------------------------------------");
        std::process::exit(1);
    } else {
        println!("    No malware detected. Codebase is clean.");
        println!("-------------------------------------------");
    }

    Ok(())
}

fn analyze_file(path: &std::path::Path, settings: &Settings) -> usize {
    let Ok(content) = std::fs::read_to_string(path) else {
        return 0;
    };

    let check_vs = settings.unicode.check_variation_selectors;
    let check_zw = settings.unicode.check_zero_width;
    let check_bidi = settings.unicode.check_bidi_controls;

    let mut found_count = 0;

    for (line_idx, line) in content.lines().enumerate() {
        for (char_idx, c) in line.chars().enumerate() {
            if c.is_ascii() {
                continue;
            }

            let u = c as usize;

            let is_bad = (check_zw && (0x200B..=0x200D).contains(&u))
                || (check_vs
                    && ((0xFE00..=0xFE0F).contains(&u) || (0xE0100..=0xE01EF).contains(&u)))
                || (check_bidi
                    && ((0x202A..=0x202E).contains(&u) || (0x2066..=0x2069).contains(&u)));

            if is_bad {
                println!(
                    "::error file={name},line={line},col={col}::Malicious Unicode (U+{u:04X}) found.",
                    line = line_idx + 1,
                    col = char_idx + 1,
                    name = path.display(),
                    u = u
                );
                found_count += 1;
                break; // No need to check further in this line
            }
        }
    }

    found_count
}
