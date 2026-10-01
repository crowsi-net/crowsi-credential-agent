struct InputPaths {
    config: std::path::PathBuf,
    draft: std::path::PathBuf,
    authorization: std::path::PathBuf,
    secret: std::path::PathBuf,
    socket: std::path::PathBuf,
}

fn write_inputs(root: &std::path::Path, material: &Material) -> InputPaths {
    let paths = InputPaths {
        config: root.join("runtime.json"),
        draft: root.join("draft.json"),
        authorization: root.join("authorization.json"),
        secret: root.join("credential.secret"),
        socket: root.join("agent.sock"),
    };
    let config = serde_json::json!({
        "schema": "crowsi://credential-agent/runtime-config/v4",
        "pa_public_key_hex": hex::encode(material.pa_public_key),
        "allowed_uid": nix::unistd::Uid::effective().as_raw(),
        "allowed_gid": nix::unistd::Gid::effective().as_raw(),
        "workload_id": WORKLOAD,
        "caller_executable_sha256": support::executable_digest(),
        "socket_path": paths.socket,
        "state_path": root.join("client-state.sqlite3"),
        "custody_path": root.join("custody.json"),
        "identity_status": support::identity_status_config(root),
        "rate_limit_per_minute": 20,
        "request_timeout_ms": 15000
    });
    write_private(&paths.config, &serde_json::to_vec(&config).expect("config"));
    write_private(&paths.draft, valid_draft().as_bytes());
    write_private(
        &paths.authorization,
        &serde_json::to_vec(&material.envelope).expect("authorization"),
    );
    write_private(&paths.secret, SECRET_MARKER);
    paths
}

fn write_private(path: &std::path::Path, content: &[u8]) {
    fs::write(path, content).expect("owner file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("owner mode");
}

fn valid_draft() -> &'static str {
    r#"{"schema":"crowsi://credentials/enrollment-draft/v1",
"operation":"credential-enroll","execution_channel":"native-ipc","information_band":"local",
"contains_secret_values":false,"credential":{"template_id":"github-app",
"credential_id":"github-app","label":"Coela GitHub App","tenant":"coela","provider":"github",
"service":"coela-github-app","purpose":"repository-read","audience":"github",
"allowed_hosts":["api.github.com"]}}"#
}
