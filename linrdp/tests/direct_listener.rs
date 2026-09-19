use std::process::Command;

#[test]
fn direct_listener_is_refused_before_configuration_or_display_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_linrdp"))
        .args(["--listener", "127.0.0.1:3389", "--config", "/does-not-exist/audit-config.yaml"])
        .env("DISPLAY", ":59999")
        .output()
        .expect("run linrdp");
    assert!(!output.status.success());
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("direct --listener mode is disabled, including console"), "{message}");
}
