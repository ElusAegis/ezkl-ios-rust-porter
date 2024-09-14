use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

pub const MOPRO_SWIFT: &str = include_str!("../../SwiftBindings/ios_ezkl.swift");
pub const MOPRO_FFI_H: &str = include_str!("../../SwiftBindings/ios_ezklFFI.h");
pub const MOPRO_MODULEMAP: &str = include_str!("../../SwiftBindings/ios_ezklFFI.modulemap");

fn main() {
    // A simple wrapper around a build command provided by mopro.
    // In the future this will likely be published in the mopro crate itself.
    // TODO - replace this with a call to mopro::build()
    // TODO - note that we are working with a differnet library name and also using macros for
    // UDL generation
    // mopro_ffi::app_config::ios::build();

    build()
}

// Load environment variables that are specified by by xcode
pub fn build() {
    let cwd = std::env::current_dir().unwrap();
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or(cwd.to_str().unwrap().to_string());
    let build_dir = format!("{}/build", manifest_dir);
    let build_dir_path = Path::new(&build_dir);
    let work_dir = mktemp_local(&build_dir_path);
    let swift_bindings_dir = work_dir.join(Path::new("SwiftBindings"));
    let bindings_out = work_dir.join("MoproiOSBindings");
    fs::create_dir(&bindings_out).expect("Failed to create bindings out directory");
    let bindings_dest = Path::new(&manifest_dir).join("MoproiOSBindings");
    let framework_out = bindings_out.join("MoproBindings.xcframework");

    let target_archs = vec![
        vec!["aarch64-apple-ios"],
        vec!["aarch64-apple-ios-sim", "x86_64-apple-ios"],
    ];

    // https://developer.apple.com/documentation/xcode/build-settings-reference#Architectures
    let mode;
    if let Ok(configuration) = std::env::var("CONFIGURATION") {
        mode = match configuration.as_str() {
            "Debug" => "debug",
            "Release" => "release",
            "debug" => "debug",
            "release" => "release",
            _ => panic!("unknown configuration"),
        };
    } else {
        mode = "debug";
    }

    // Take a list of architectures, build them, and combine them into
    // a single universal binary/archive
    let build_combined_archs = |archs: &Vec<&str>| -> PathBuf {
        let out_lib_paths: Vec<PathBuf> = archs
            .iter()
            .map(|arch| {
                Path::new(&build_dir).join(Path::new(&format!(
                    "{}/{}/{}/libios_ezkl.a",
                    build_dir, arch, mode
                )))
            })
            .collect();
        for arch in archs {
            install_arch(arch.to_string());
            let mut build_cmd = Command::new("cargo");
            build_cmd.arg("build");
            if mode == "release" {
                build_cmd.arg("--release");
            }
            build_cmd
                .arg("--lib")
                .env("CARGO_BUILD_TARGET_DIR", &build_dir)
                .env("CARGO_BUILD_TARGET", arch)
                .spawn()
                .expect("Failed to spawn cargo build")
                .wait()
                .expect("cargo build errored");
        }
        // now lipo the libraries together
        let mut lipo_cmd = Command::new("lipo");
        let lib_out = mktemp_local(&build_dir_path).join("libios_ezkl.a");
        lipo_cmd
            .arg("-create")
            .arg("-output")
            .arg(lib_out.to_str().unwrap());
        for p in out_lib_paths {
            lipo_cmd.arg(p.to_str().unwrap());
        }
        lipo_cmd
            .spawn()
            .expect("Failed to spawn lipo")
            .wait()
            .expect("lipo command failed");

        lib_out
    };

    write_bindings_swift(&swift_bindings_dir);
    fs::rename(
        &swift_bindings_dir.join("ios_ezkl.swift"),
        &bindings_out.join("ios_ezkl.swift"),
    )
    .expect("Failed to move ios_ezkl.swift into place");
    let out_lib_paths: Vec<PathBuf> = target_archs
        .iter()
        .map(|v| build_combined_archs(v))
        .collect();

    let mut xcbuild_cmd = Command::new("xcodebuild");
    xcbuild_cmd.arg("-create-xcframework");
    for lib_path in out_lib_paths {
        xcbuild_cmd
            .arg("-library")
            .arg(lib_path.to_str().unwrap())
            .arg("-headers")
            .arg(swift_bindings_dir.to_str().unwrap());
    }
    xcbuild_cmd
        .arg("-output")
        .arg(framework_out.to_str().unwrap())
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    if let Ok(info) = fs::metadata(&bindings_dest) {
        if !info.is_dir() {
            panic!("framework directory exists and is not a directory");
        }
        fs::remove_dir_all(&bindings_dest).expect("Failed to remove framework directory");
    }
    fs::rename(&bindings_out, &bindings_dest).expect("Failed to move framework into place");
    // Copy the mopro.swift file to the output directory
    cleanup_tmp_local(&build_dir_path)
}

pub fn write_bindings_swift(out_dir: &Path) {
    if let Ok(info) = fs::metadata(out_dir) {
        if !info.is_dir() {
            panic!("out_dir exists and is not a directory");
        }
    } else {
        fs::create_dir(out_dir).expect("Failed to create output dir");
    }
    fs::write(out_dir.join("ios_ezkl.swift"), MOPRO_SWIFT).expect("Failed to write ios_ezkl.swift");
    fs::write(out_dir.join("ios_ezklFFI.h"), MOPRO_FFI_H).expect("Failed to write ios_ezklFFI.h");
    fs::write(out_dir.join("module.modulemap"), MOPRO_MODULEMAP)
        .expect("Failed to write module.modulemap");
}

pub fn mktemp() -> PathBuf {
    let dir = std::env::temp_dir().join(Path::new(&Uuid::new_v4().to_string()));
    fs::create_dir(&dir).expect("Failed to create tmpdir");
    dir
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

pub fn cleanup_tmp_local(build_path: &Path) {
    fs::remove_dir_all(tmp_local(build_path)).expect("Failed to remove tmpdir");
}

pub fn install_ndk() {
    Command::new("cargo")
        .arg("install")
        .arg("cargo-ndk")
        .spawn()
        .expect("Failed to spawn cargo, is it installed?")
        .wait()
        .expect("Failed to install cargo-ndk");
}

pub fn install_arch(arch: String) {
    Command::new("rustup")
        .arg("target")
        .arg("add")
        .arg(arch.clone())
        .spawn()
        .expect("Failed to spawn rustup, is it installed?")
        .wait()
        .expect(format!("Failed to install target architecture {}", arch).as_str());
}

pub fn install_archs() {
    let archs = vec![
        "x86_64-apple-ios",
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
        "aarch64-linux-android",
        "armv7-linux-androideabi",
        "i686-linux-android",
        "x86_64-linux-android",
    ];
    for arch in archs {
        install_arch(arch.to_string());
    }
}
