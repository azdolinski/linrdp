//! Each library variant gets a fresh process because the real loader uses OnceLock.
#![allow(dead_code)]
#[path = "../src/pam.rs"]
mod pam;
use std::{fs, process::Command};

#[test]
fn controlled_pam_child() {
    let Ok(case) = std::env::var("LINRDP_TEST_PAM_CASE") else { return; };
    let result = pam::authenticate("audit-fixture", "unused");
    if case == "auth" || case == "account" {
        assert_eq!(result, Ok(false));
    } else {
        assert!(matches!(result, Err(pam::NoVerdict::BackendFailed(_))), "{result:?}");
        assert!(matches!(pam::account_valid("audit-fixture"), Err(pam::NoVerdict::BackendFailed(_))));
    }
}

#[test]
fn real_loader_refuses_broken_libraries_and_pam_denials() {
    let dir = std::env::temp_dir().join(format!("linrdp-pam-loader-test-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    let _cleanup = Cleanup(dir.clone());
    for case in ["missing-symbol", "start", "auth", "account", "broken-library"] {
        let lib = dir.join("libpam.so.0");
        if case == "broken-library" {
            // Both names exist but neither can load. This must not be mistaken for no policy.
            fs::write(&lib, b"not a shared object").unwrap();
            fs::write(dir.join("libpam.so"), b"not a shared object").unwrap();
        } else {
            let source = format!(r#"
int pam_start(void*a,void*b,void*c,void**d){{*d=(void*)1;return {};}}
int pam_authenticate(void*a,int b){{return {};}}
int pam_acct_mgmt(void*a,int b){{return {};}}
int pam_end(void*a,int b){{return 0;}}
int pam_setcred(void*a,int b){{return 0;}}
int pam_open_session(void*a,int b){{return 0;}}
int pam_close_session(void*a,int b){{return 0;}}
{}
"#, if case == "start" {4} else {0}, if case == "auth" {7} else {0},
                if case == "account" {7} else {0},
                if case == "missing-symbol" {""} else {"void *pam_getenvlist(void*a){return 0;}"});
            fs::write(dir.join("pam.c"), source).unwrap();
            assert!(Command::new("cc").args(["-shared", "-fPIC", "-Wl,--no-as-needed", "-lc"]).arg(dir.join("pam.c"))
                .arg("-o").arg(&lib).status().unwrap().success());
        }
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "controlled_pam_child", "--nocapture"])
            .env("LINRDP_TEST_PAM_CASE", case).env("LD_LIBRARY_PATH", &dir)
            .output().unwrap();
        assert!(output.status.success(), "{case}: {} {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    }
}
