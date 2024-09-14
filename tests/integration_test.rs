use ezkl::commands::DEFAULT_DISABLE_SELECTOR_COMPRESSION;
use ios_ezkl::setup_keys;
use std::sync::Once;

static INIT: Once = Once::new();
const INPUT_JSON_PATH: &str = "tests/ezkl-sample/input.json";
const COMPILED_CIRCUIT_PATH: &str = "tests/ezkl-sample/network.ezkl";
const SETTINGS_PATH: &str = "tests/ezkl-sample/settings.json";
const SRS_PATH: &str = "tests/ezkl-sample/kzg.srs";
const VK_PATH: &str = "tests/ezkl-sample/vk.key";
const PK_PATH: &str = "tests/ezkl-sample/pk.key";

// This function should run `cargo run --bin gen-keys` to generate the proving and verifying keys.
fn setup_keys_once() {
    INIT.call_once(|| {
        setup_keys(
            COMPILED_CIRCUIT_PATH.to_string().parse().unwrap(),
            Some(SRS_PATH.to_string().parse().unwrap()),
            VK_PATH.to_string().parse().unwrap(),
            PK_PATH.to_string().parse().unwrap(),
            None,
            DEFAULT_DISABLE_SELECTOR_COMPRESSION.parse().unwrap(),
        )
        .unwrap();
    });
}

#[tokio::test]
async fn test_gen_witness_wrapper() {
    setup_keys_once();

    // 1. Read input JSON and file paths
    let file = std::fs::read(INPUT_JSON_PATH).expect("Failed to read input JSON file");
    let input_json = String::from_utf8(file).expect("Failed to parse input JSON file");

    // 2. Call the gen_witness_wrapper function
    let witness = ios_ezkl::gen_witness_wrapper(
        input_json.to_string(),
        COMPILED_CIRCUIT_PATH.to_string(),
        VK_PATH.to_string(),
        SRS_PATH.to_string(),
    )
    .await;

    // 3. Assert that witness generation was successful
    assert!(witness.is_ok(), "Witness generation failed: {:?}", witness);
}

#[tokio::test]
async fn test_end_to_end() {
    setup_keys_once();

    // 1. Read input JSON and file paths
    let file = std::fs::read(INPUT_JSON_PATH).expect("Failed to read input JSON file");
    let input_json = String::from_utf8(file).expect("Failed to parse input JSON file");

    // 2. Call the gen_witness_wrapper function
    let witness = ios_ezkl::gen_witness_wrapper(
        input_json.to_string(),
        COMPILED_CIRCUIT_PATH.to_string(),
        VK_PATH.to_string(),
        SRS_PATH.to_string(),
    )
    .await;

    // 3. Assert that witness generation was successful
    assert!(witness.is_ok(), "Witness generation failed: {:?}", witness);
    let witness = witness.unwrap();

    // 4. Generate proof using prove_wrapper
    let proof = ios_ezkl::prove_wrapper(
        witness,
        COMPILED_CIRCUIT_PATH.to_string(),
        PK_PATH.to_string(),
        Some(SRS_PATH.to_string()),
    );

    // 5. Assert that proof generation was successful
    assert!(proof.is_ok(), "Proof generation failed: {:?}", proof);
    let proof_json = proof.unwrap();

    // 6. Verify proof using verify_wrapper
    let verify_result = ios_ezkl::verify_wrapper(
        proof_json.to_string(),
        SETTINGS_PATH.to_string(),
        VK_PATH.to_string(),
        Some(SRS_PATH.to_string()),
    );

    // 7. Assert that proof verification was successful
    assert!(
        verify_result.is_ok(),
        "Proof verification failed: {:?}",
        verify_result
    );
}
