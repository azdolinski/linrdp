//! Builds the vendored x264 (statically) and generates FFI bindings.
//!
//! The x264 sources live in `vendor/x264` at the workspace root. The build
//! runs x264's own `configure` out-of-tree (static, OpenCL disabled) and
//! `make`, then links the resulting `libx264.a` into the binary — no system
//! libx264 is needed at build or run time.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace = manifest.parent().and_then(Path::parent).expect("workspace root").to_path_buf();
    let src_dir = workspace.join("vendor").join("x264");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let build_dir = out_dir.join("build");
    std::fs::create_dir_all(&build_dir).expect("create build dir");

    // 1. Configure (out-of-tree). Re-run only when the source changes.
    println!("cargo:rerun-if-changed={}", src_dir.join("configure").display());
    println!("cargo:rerun-if-changed={}", src_dir.join("Makefile").display());
    println!("cargo:rerun-if-changed={}", src_dir.join("x264.h").display());
    let configured = build_dir.join("Makefile");
    if !configured.exists() {
        let status = Command::new("bash")
            .arg(src_dir.join("configure"))
            .current_dir(&build_dir)
            .env_remove("CFLAGS")
            .env_remove("LDFLAGS")
            .args(["--enable-static", "--disable-opencl", "--enable-pic"])
            .status()
            .expect("run x264 configure");
        assert!(status.success(), "x264 configure failed");
    }

    // 2. Make. Configure generated config.mak in the build dir.
    let jobs = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    let status = Command::new("make")
        .arg("-j")
        .arg(jobs.to_string())
        .current_dir(&build_dir)
        .status()
        .expect("run x264 make");
    assert!(status.success(), "x264 make failed");

    // 3. Static link directives. libx264.a needs m, pthread and dl.
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=x264");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rustc-link-lib=dl");

    // 4. Bindings over the vendored header plus the generated x264_config.h.
    let buildver: String = {
        let header = std::fs::read_to_string(src_dir.join("x264.h")).expect("x264.h");
        header
            .lines()
            .find_map(|l| l.trim().strip_prefix("#define X264_BUILD "))
            .and_then(|v| v.trim().parse().ok())
            .expect("X264_BUILD in x264.h")
    };

    // x264.h requires <stdint.h> to be included before it; use a shim.
    let shim = out_dir.join("x264_shim.h");
    std::fs::write(
        &shim,
        "#include <stdint.h>\n#include <stdarg.h>\n#include <stdio.h>\n#include <x264.h>\n",
    )
    .expect("write shim");

    let mut builder = bindgen::builder()
        .raw_line(format!(
            "pub unsafe fn x264_encoder_open(params: *mut x264_param_t) -> *mut x264_t {{\n    x264_encoder_open_{}(params)\n}}",
            buildver
        ))
        .header(shim.to_str().expect("shim path"))
        .clang_arg("-std=c99")
        .clang_arg(format!("-I{}", build_dir.display()))
        .clang_arg(format!("-I{}", src_dir.display()))
        .size_t_is_usize(true);

    let bindings = builder.generate().expect("bindgen x264");
    bindings
        .write_to_file(out_dir.join("x264.rs"))
        .expect("write bindings");
}
