use camino::Utf8Path;
use std::fs;
use std::fs::remove_dir_all;
use std::path::{Path, PathBuf};
use std::process::Command;
use uniffi_bindgen::bindings::SwiftBindingGenerator;
use uniffi_bindgen::library_mode::generate_bindings;
use uuid::Uuid;

const LIBRARY_NAME: &str = "ios_ezkl";

fn main() {
    let mode = determine_build_mode();

    build_bindings(LIBRARY_NAME, mode.to_string());
}

fn determine_build_mode() -> &'static str {
    match std::env::var("CONFIGURATION")
        .unwrap_or_else(|_| "release".to_string())
        .to_lowercase()
        .as_str()
    {
        "debug" => "debug",
        "release" => "release",
        _ => "release",
    }
}

fn build_bindings(library_name: &str, mode: String) {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| {
        std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    });
    let build_dir = PathBuf::from(&manifest_dir).join("build");
    // Create a tmp directory to store the bindings and the combined library
    let tmp_dir = mktemp_local(&build_dir);

    let swift_bindings_dir = tmp_dir.join("SwiftBindings");
    let bindings_out = create_bindings_out_dir(&tmp_dir);
    let bindings_dest = Path::new(&manifest_dir).join("EzklCoreBindings");
    let framework_out = bindings_out.join("EzklCore.xcframework");

    let target_archs = vec![
        vec!["aarch64-apple-ios"],
        vec!["aarch64-apple-ios-sim", "x86_64-apple-ios"],
    ];

    // write_swift_bindings(library_name, swift_bindings_dir, &bindings_out);

    let out_lib_paths: Vec<PathBuf> = target_archs
        .iter()
        .map(|archs| build_combined_archs(library_name, archs, &build_dir, &mode))
        .collect();

    let out_dylib_path = build_dir.join(format!(
        "{}/{}/lib{}.dylib",
        target_archs[0][0], mode, library_name
    ));

    generate_ios_bindings(&out_dylib_path, swift_bindings_dir.as_path())
        .expect("TODO: panic message");

    fs::rename(
        swift_bindings_dir.join(format!("{}.swift", library_name)),
        bindings_out.join("EzklCore.swift"),
    )
    .expect("Failed to copy bindings");

    create_xcframework(&out_lib_paths, &swift_bindings_dir, &framework_out);

    if bindings_dest.exists() {
        fs::remove_dir_all(&bindings_dest).expect("Failed to remove existing bindings directory");
    }

    fs::rename(&bindings_out, &bindings_dest).expect("Failed to move framework into place");

    cleanup_temp_dirs(&build_dir);
}

fn create_bindings_out_dir(build_dir: &PathBuf) -> PathBuf {
    let bindings_out = build_dir.join("EzklCoreBindings");
    fs::create_dir_all(&bindings_out).expect("Failed to create bindings output directory");
    bindings_out
}

fn build_combined_archs(
    library_name: &str,
    archs: &[&str],
    build_dir: &PathBuf,
    mode: &str,
) -> PathBuf {
    let out_lib_paths: Vec<PathBuf> = archs
        .iter()
        .map(|&arch| {
            build_for_arch(arch, build_dir, mode);
            build_dir
                .join(arch)
                .join(mode)
                .join(format!("lib{}.a", library_name))
        })
        .collect();

    let lib_out = mktemp_local(&build_dir).join(format!("lib{}.a", library_name));

    let mut lipo_cmd = Command::new("lipo");
    lipo_cmd
        .arg("-create")
        .arg("-output")
        .arg(lib_out.to_str().unwrap());
    for lib_path in &out_lib_paths {
        lipo_cmd.arg(lib_path.to_str().unwrap());
    }

    let status = lipo_cmd.status().expect("Failed to run lipo command");
    if !status.success() {
        panic!("lipo command failed with status: {}", status);
    }

    lib_out
}

fn build_for_arch(arch: &str, build_dir: &PathBuf, mode: &str) {
    install_arch(arch);

    let mut build_cmd = Command::new("cargo");
    build_cmd.arg("build");
    if mode == "release" {
        build_cmd.arg("--release");
    }
    build_cmd
        .arg("--lib")
        .env("CARGO_BUILD_TARGET_DIR", build_dir)
        .env("CARGO_BUILD_TARGET", arch);

    let status = build_cmd.status().expect("Failed to run cargo build");
    if !status.success() {
        panic!("cargo build failed for architecture: {}", arch);
    }
}

fn create_xcframework(
    lib_paths: &[PathBuf],
    swift_bindings_dir: &PathBuf,
    framework_out: &PathBuf,
) {
    let mut xcbuild_cmd = Command::new("xcodebuild");
    xcbuild_cmd.arg("-create-xcframework");

    // Print all lib paths
    for lib_path in lib_paths {
        println!("lib_path: {:?}", lib_path);
    }

    for lib_path in lib_paths {
        xcbuild_cmd.arg("-library");
        xcbuild_cmd.arg(lib_path.to_str().unwrap());
        xcbuild_cmd.arg("-headers");
        xcbuild_cmd.arg(swift_bindings_dir.to_str().unwrap());
    }

    xcbuild_cmd.arg("-output");
    xcbuild_cmd.arg(framework_out.to_str().unwrap());

    let status = xcbuild_cmd.status().expect("Failed to run xcodebuild");
    if !status.success() {
        panic!("xcodebuild failed with status: {}", status);
    }
}

fn install_arch(arch: &str) {
    let status = Command::new("rustup")
        .arg("target")
        .arg("add")
        .arg(arch)
        .status()
        .expect("Failed to run rustup command");

    if !status.success() {
        panic!("Failed to install target architecture: {}", arch);
    }
}

fn tmp_local(build_path: &Path) -> PathBuf {
    let tmp_path = build_path.join("tmp");
    if let Ok(metadata) = fs::metadata(&tmp_path) {
        if !metadata.is_dir() {
            panic!("non-directory tmp");
        }
    } else {
        fs::create_dir_all(&tmp_path).expect("Failed to create local tmpdir");
    }
    tmp_path
}

pub fn mktemp_local(build_path: &Path) -> PathBuf {
    let dir = tmp_local(build_path).join(&Uuid::new_v4().to_string());
    fs::create_dir(&dir).expect("Failed to create tmpdir");
    dir
}

fn cleanup_temp_dirs(build_dir: &PathBuf) {
    let tmp_dir = build_dir.join("tmp");
    if tmp_dir.exists() {
        fs::remove_dir_all(tmp_dir).expect("Failed to remove temporary directories");
    }
}

fn generate_ios_bindings(dylib_path: &Path, binding_dir: &Path) -> Result<(), std::io::Error> {
    if binding_dir.exists() {
        remove_dir_all(binding_dir)?;
    }

    generate_bindings(
        Utf8Path::from_path(&dylib_path).ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid dylib path",
        ))?,
        None,
        &SwiftBindingGenerator,
        None,
        Utf8Path::from_path(&binding_dir).ok_or(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Invalid swift files directory",
        ))?,
        true,
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(())
}
