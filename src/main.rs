use clap::{Arg, Command, ArgAction};
use std::process::exit;
use std::fs::File;
use std::io::{BufReader, BufRead};
use hibp_check::{check_next, check_password};

/// Accepts either a single password (indicated by flag -p) or a list of passwords contained in a .txt document (indicated by flag -l)
/// If passing a .txt, passwords in the document should be formatted one to a line. 
fn main() {
    //! A simple cli tool to check passwords against HaveIBeenPwned. This module queries the HIBP password API 
    //! which is free and not rate limited. The API protects anaonymity using sha1 hashing combined with k-anonymity 
    //! and this module does not save passwords passed to it nor does it display them in outputs by defualt, though
    //! if users wish to display passwords in output they may pass -s   
    let matches = Command::new("hibp")
        .version("0.1.2")
        .author("Nathaniel Adamian")
        .about("Check if passwords have been accessed in a databreach")
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .value_name("PASSWORD")
                .help("Check a single password")
                .conflicts_with("list")
                .action(ArgAction::Set)
        )
        .arg(
            Arg::new("list")
                .short('l')
                .long("list")
                .value_name("FILE")
                .help("Check passwords from a file (one per line)")
                .conflicts_with("password")
                .action(ArgAction::Set)
        )
        .arg(
            Arg::new("show_password")
            .short('s')
            .long("show")
            .help("Display the actual password in the output comparison. Defaults to false if flag not passed.")
            .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("anonymous_hash")
            .short('a')
            .long("anonymous")
            .help("Accept a sha1 hash rather than a raw text password. Defaults to false.")
            .action(ArgAction::SetTrue)
        )
        .get_matches();

    let show_pass_value = matches.get_flag("show_password");
    let take_anonymous_hash = matches.get_flag("anonymous_hash");

    if let Some(password_str) = matches.get_one::<String>("password") {
        _ = check_password(password_str, show_pass_value, take_anonymous_hash, true);
    } else if let Some(file_path_str) = matches.get_one::<String>("list") {
        let file = match File::open(file_path_str) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Error: Failed to open file '{}': {}", file_path_str, e);
                exit(1);
            }
        };
        let reader = BufReader::new(file);
        for line_result in reader.lines() {
            match line_result {
                Ok(password_line) => {
                    let trimmed_password = password_line.trim();
                    if !trimmed_password.is_empty() {
                        _ = check_password(trimmed_password, show_pass_value, take_anonymous_hash, true);
                    }
                }
                Err(e) => {
                    eprintln!("Error reading a line from the file: {}", e);
                }
            }
        }
    } else {
        check_next();
    }
}
