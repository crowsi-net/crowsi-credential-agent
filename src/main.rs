mod command;
mod failure;
mod inspection_command;

use failure::Failure;

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == ["sample-readiness"] {
        print_json(&crowsi_credential_agent::sample_readiness());
        return;
    }
    if let Some(report) = command::diagnosis(&arguments) {
        print_json(&report);
        return;
    }
    if let Some(result) = inspection_command::inspection(&arguments) {
        match result {
            Ok(report) => print_json(&report),
            Err(error) => fail_ipc(error),
        }
        return;
    }
    if let Some(result) = command::prepare_request(&arguments) {
        match result {
            Ok(request) => print_json(&request),
            Err(error) => fail_ipc(error),
        }
        return;
    }
    match command::dispatch(&arguments) {
        Ok(()) => {}
        Err(Failure::Usage) => usage(),
        Err(Failure::ResponseEncoding) => fail("response-encoding-failed", 70),
        Err(Failure::Ipc(error)) => fail_ipc(error),
    }
}

fn print_json(value: &impl serde::Serialize) {
    match serde_json::to_string(value) {
        Ok(document) => println!("{document}"),
        Err(_) => fail("response-encoding-failed", 70),
    }
}

fn fail(reason: &str, code: i32) -> ! {
    eprintln!("crowsi-credential-agent: {reason}");
    std::process::exit(code);
}

fn fail_ipc(error: crowsi_credential_broker::IpcError) -> ! {
    let (reason, code) = failure::reason(error);
    fail(reason, code)
}

fn usage() -> ! {
    eprintln!("usage: crowsi-credential-agent serve[-one] --config <absolute-json>");
    eprintln!("       crowsi-credential-agent doctor --config <absolute-json>");
    eprintln!("       crowsi-credential-agent credential inspect --config <json> --draft <json>");
    eprintln!(
        "       crowsi-credential-agent credential enroll --config <json> --draft <json> --authorization <json> --secret-file <file>"
    );
    eprintln!(
        "       crowsi-credential-agent credential enroll-stdin --config <json> --draft <json> --authorization <json>"
    );
    eprintln!(
        "       crowsi-credential-agent credential prepare --draft <json> --request-id <id> --secret-length <bytes> --secret-sha256 <digest>"
    );
    std::process::exit(64)
}
