#[test]
fn dbg_clap_parse() {
    let cli = deploy::cli::Cli::try_parse_from(["deploy", "checkpoint", "production", "deploy-004", "--dry-run", "--yes"]);
    println!("cli parse result: {:?}", cli);
}
