use std::path::Path;

use crowsi_credential_agent::CredentialInspectionV1;
use crowsi_credential_broker::IpcError;

pub fn inspection(arguments: &[String]) -> Option<Result<CredentialInspectionV1, IpcError>> {
    let [credential, inspect, cf, config, df, draft] = arguments else {
        return None;
    };
    if credential != "credential" || inspect != "inspect" || cf != "--config" || df != "--draft" {
        return None;
    }
    Some(
        crowsi_credential_agent::inspect_platform_custody_credential(
            Path::new(config),
            Path::new(draft),
        ),
    )
}
