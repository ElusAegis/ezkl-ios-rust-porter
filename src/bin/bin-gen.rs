fn main() {
    // Check if the script has `generate` as the first argument, this means we are generating the bindings
    // And all preliminary steps should be done before generating the bindings
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "generate" {
        uniffi::uniffi_bindgen_main();

        // Run the `cargo run --bin ios` to update the bindings for the iOS project
        let mut cargo_run = std::process::Command::new("cargo");
        cargo_run
            .arg("run")
            .arg("--bin")
            .arg("ios")
            .spawn()
            .expect("cargo run errored")
            .wait()
            .expect("cargo run failed");

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
        .arg("SwiftBindings")
        .spawn()
        .expect("cargo run errored")
        .wait()
        .expect("cargo run failed");
}
