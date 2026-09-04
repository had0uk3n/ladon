fn main() {
    if let Err(message) = ladon_app::run_desktop() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}
