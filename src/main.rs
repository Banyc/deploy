use deploy::cli;
use std::error::Error as _;

fn main() {
    if let Err(e) = cli::run() {
        eprintln!("error: {e}");
        // Print any underlying cause chain.
        let mut src: Option<&dyn std::error::Error> = e.source();
        while let Some(c) = src {
            eprintln!("  caused by: {c}");
            src = c.source();
        }
        std::process::exit(1);
    }
}
