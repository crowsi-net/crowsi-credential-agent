use std::{io::IsTerminal, path::Path};

use crowsi_credential_broker::{EnrollmentReceiptV1, IpcError};

use crate::failure::Failure;

pub fn diagnosis(arguments: &[String]) -> Option<serde_json::Value> {
    let [doctor, flag, config] = arguments else {
        return None;
    };
    if doctor != "doctor" || flag != "--config" {
        return None;
    }
    serde_json::to_value(crowsi_credential_agent::diagnose_platform_custody_runtime(
        Path::new(config),
    ))
    .ok()
}

pub fn dispatch(arguments: &[String]) -> Result<(), Failure> {
    match arguments {
        [command, flag, config] if command == "serve" && flag == "--config" => {
            serve(Path::new(config), false)
        }
        [command, flag, config] if command == "serve-one" && flag == "--config" => {
            serve(Path::new(config), true)
        }
        [
            credential,
            enroll,
            cf,
            config,
            df,
            draft,
            af,
            authorization,
            sf,
            secret,
        ] if credential == "credential"
            && enroll == "enroll"
            && cf == "--config"
            && df == "--draft"
            && af == "--authorization"
            && sf == "--secret-file" =>
        {
            let receipt = crowsi_credential_agent::enroll_from_owner_files(
                Path::new(config),
                Path::new(draft),
                Path::new(authorization),
                Path::new(secret),
            )
            .map_err(Failure::Ipc)?;
            print_receipt(&receipt)
        }
        [credential, enroll, cf, config, df, draft, af, authorization]
            if credential == "credential"
                && enroll == "enroll-stdin"
                && cf == "--config"
                && df == "--draft"
                && af == "--authorization" =>
        {
            if std::io::stdin().is_terminal() {
                return Err(Failure::Ipc(IpcError::InvalidFrame));
            }
            let receipt = crowsi_credential_agent::enroll_from_owner_stream(
                Path::new(config),
                Path::new(draft),
                Path::new(authorization),
                std::io::stdin().lock(),
            )
            .map_err(Failure::Ipc)?;
            print_receipt(&receipt)
        }
        _ => Err(Failure::Usage),
    }
}

pub fn prepare_request(
    arguments: &[String],
) -> Option<Result<crowsi_local_control_bridge::ControlRequestV1, IpcError>> {
    let [
        credential,
        prepare,
        df,
        draft,
        idf,
        request_id,
        lf,
        length,
        hf,
        digest,
    ] = arguments
    else {
        return None;
    };
    if credential != "credential"
        || prepare != "prepare"
        || df != "--draft"
        || idf != "--request-id"
        || lf != "--secret-length"
        || hf != "--secret-sha256"
    {
        return None;
    }
    let Ok(length) = length.parse::<u64>() else {
        return Some(Err(IpcError::InvalidFrame));
    };
    Some(
        crowsi_credential_agent::load_enrollment_draft(Path::new(draft))
            .and_then(|value| value.control_request(request_id, length, digest)),
    )
}

fn serve(config_path: &Path, once: bool) -> Result<(), Failure> {
    let config = crowsi_credential_agent::load_runtime_config(config_path).map_err(Failure::Ipc)?;
    if once {
        let receipt =
            crowsi_credential_agent::serve_platform_custody_once(&config).map_err(Failure::Ipc)?;
        return print_receipt(&receipt);
    }
    let shutdown = crowsi_credential_agent::install_shutdown_flag().map_err(Failure::Ipc)?;
    crowsi_credential_agent::serve_platform_custody_until(&config, &shutdown).map_err(Failure::Ipc)
}

fn print_receipt(value: &EnrollmentReceiptV1) -> Result<(), Failure> {
    let document = serde_json::to_string(value).map_err(|_| Failure::ResponseEncoding)?;
    println!("{document}");
    Ok(())
}
