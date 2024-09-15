use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

fn main() {
    let cwd = std::env::current_dir().unwrap();
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or(cwd.to_str().unwrap().to_string());
    let build_dir = format!("{}/build", manifest_dir);
    let build_dir_path = Path::new(&build_dir);
    let work_dir = mktemp_local(build_dir_path);
    let swift_bindings_dir = build_dir_path.join(Path::new("tmp/SwiftBindings"));

    // Check if the script has `generate` as the first argument, this means we are generating the bindings
    // And all preliminary steps should be done before generating the bindings
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "generate" {
        uniffi::uniffi_bindgen_main();

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
            mode = "release";
        }

        build_bindings(
            manifest_dir,
            work_dir,
            build_dir,
            swift_bindings_dir,
            mode.to_string(),
        );
        return;
    }

    // Otherwise, we are in the prelimary step, and we need to check if we need to build the library
    // And call ourselves with the `generate` argument to generate the bindings

    // Rebuild the library
    let lib_path = std::path::Path::new("target/debug/libios_ezkl.a");
    // If it does not exist, then we need to build the library
    let mut cargo_build = std::process::Command::new("cargo");
    cargo_build
        .arg("build")
        .spawn()
        .expect("cargo build errored")
        .wait()
        .expect("cargo build failed");

    // Run the script with the `generate` argument
    let mut cargo_run = std::process::Command::new("cargo");
    cargo_run
        .arg("run")
        .arg("--bin")
        .arg("bin-gen")
        .arg("generate")
        .arg("--library")
        .arg(lib_path.to_str().unwrap())
        .arg("--language")
        .arg("swift")
        .arg("--out-dir")
        .arg(swift_bindings_dir.as_path())
        .spawn()
        .expect("cargo run errored")
        .wait()
        .expect("cargo run failed");
}

// Load environment variables that are specified by by xcode
pub fn build_bindings(
    manifest_dir: String,
    work_dir: PathBuf,
    build_dir: String,
    swift_bindings_dir: PathBuf,
    mode: String,
) {
    let build_dir_path = Path::new(&build_dir);

    let bindings_out = work_dir.join("EzklCoreBindings");
    fs::create_dir(&bindings_out).expect("Failed to create bindings out directory");
    let bindings_dest = Path::new(&manifest_dir).join("EzklCoreBindings");
    let framework_out = bindings_out.join("EzklCore.xcframework");

    #[allow(clippy::useless_vec)]
    let target_archs = vec![
        vec!["aarch64-apple-ios"],
        vec!["aarch64-apple-ios-sim", "x86_64-apple-ios"],
    ];

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
        let lib_out = mktemp_local(build_dir_path).join("libios_ezkl.a");
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

    // write_bindings_swift(&swift_bindings_dir);
    // print the path of the swift bindings directory
    // and print the contents of the directory
    println!("swift_bindings_dir: {:?}", swift_bindings_dir);
    let swift_bindings_dir_contents = fs::read_dir(&swift_bindings_dir).unwrap();
    for entry in swift_bindings_dir_contents {
        let entry = entry.unwrap();
        println!("{:?}", entry.path());
    }
    fs::rename(
        swift_bindings_dir.join("ios_ezkl.swift"),
        bindings_out.join("EzklCore.swift"),
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
    cleanup_tmp_local(build_dir_path)
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
    let dir = tmp_local(build_path).join(Uuid::new_v4().to_string());
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
        .unwrap_or_else(|_| panic!("Failed to install target architecture {}", arch));
}

pub fn install_archs() {
    let archs = vec![
        "x86_64-apple-ios",
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
    ];
    for arch in archs {
        install_arch(arch.to_string());
    }
}
