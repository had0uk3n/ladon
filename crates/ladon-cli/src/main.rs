use std::process::ExitCode;

fn main() -> ExitCode {
    let code = ladon::execute_cli(
        std::env::args(),
        &ladon::LocalRpcTransport,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    ExitCode::from(if code == 0 { 0 } else { 2 })
}
