use ezkl::commands::DEFAULT_DISABLE_SELECTOR_COMPRESSION;
use ezkl::graph::{GraphCircuit, GraphWitness};
use ezkl::pfsys::{create_keys, save_pk, save_vk};
use ezkl::Commitments;
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::poly::ipa::commitment::IPACommitmentScheme;
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use ios_ezkl::testing::deserialize_params_prover;
use std::path::PathBuf;
use std::sync::Once;

static INIT: Once = Once::new();
const INPUT_JSON_PATH: &str = "tests/ezkl-sample/input.json";
const COMPILED_CIRCUIT_PATH: &str = "tests/ezkl-sample/network.ezkl";
const SETTINGS_PATH: &str = "tests/ezkl-sample/settings.json";
const SRS_PATH: &str = "tests/ezkl-sample/kzg.srs";
const VK_PATH: &str = "tests/ezkl-sample/vk.key";
const PK_PATH: &str = "tests/ezkl-sample/pk.key";

pub fn setup_keys(
    compiled_circuit: PathBuf,
    serialized_srs: Option<&[u8]>,
    vk_path: PathBuf,
    pk_path: PathBuf,
    witness: Option<PathBuf>,
    disable_selector_compression: bool,
) -> Result<String, ezkl::EZKLError> {
    // these aren't real values so the sanity checks are mostly meaningless

    let mut circuit = GraphCircuit::load(compiled_circuit)?;

    if let Some(witness) = witness {
        let data = GraphWitness::from_path(witness)?;
        circuit.load_graph_witness(&data)?;
    }

    let logrows = circuit.settings().run_args.logrows;
    let commitment: Commitments = circuit.settings().run_args.commitment.into();

    let pk = match commitment {
        Commitments::KZG => {
            let params =
                deserialize_params_prover::<KZGCommitmentScheme<Bn256>>(serialized_srs, logrows)?;
            create_keys::<KZGCommitmentScheme<Bn256>, GraphCircuit>(
                &circuit,
                &params,
                disable_selector_compression,
            )?
        }
        Commitments::IPA => {
            let params = deserialize_params_prover::<IPACommitmentScheme<G1Affine>>(
                serialized_srs,
                logrows,
            )?;
            create_keys::<IPACommitmentScheme<G1Affine>, GraphCircuit>(
                &circuit,
                &params,
                disable_selector_compression,
            )?
        }
    };
    save_vk::<G1Affine>(&vk_path, pk.get_vk())?;
    save_pk::<G1Affine>(&pk_path, &pk)?;
    Ok(String::new())
}

// This function should run `cargo run --bin gen-keys` to generate the proving and verifying keys.
fn setup_keys_once() {
    INIT.call_once(|| {
        setup_keys(
            COMPILED_CIRCUIT_PATH.to_string().parse().unwrap(),
            Some(&std::fs::read(SRS_PATH).expect("Failed to read srs file")),
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
    let compiled_circuit =
        std::fs::read(COMPILED_CIRCUIT_PATH).expect("Failed to read circuit file");
    let vk = std::fs::read(VK_PATH).expect("Failed to read vk file");
    let srs = std::fs::read(SRS_PATH).expect("Failed to read srs file");

    // 2. Call the gen_witness_wrapper function
    let witness =
        ios_ezkl::gen_witness_wrapper(input_json.to_string(), compiled_circuit, vk, srs).await;

    // 3. Assert that witness generation was successful
    assert!(witness.is_ok(), "Witness generation failed: {:?}", witness);
}

#[tokio::test]
async fn test_end_to_end() {
    setup_keys_once();

    // 1. Read input JSON and file paths
    let input_file = std::fs::read(INPUT_JSON_PATH).expect("Failed to read input JSON file");
    let input_json = String::from_utf8(input_file).expect("Failed to parse input JSON file");
    let compiled_circuit =
        std::fs::read(COMPILED_CIRCUIT_PATH).expect("Failed to read circuit file");
    let vk = std::fs::read(VK_PATH).expect("Failed to read vk file");
    let srs = std::fs::read(SRS_PATH).expect("Failed to read srs file");
    let pk = std::fs::read(PK_PATH).expect("Failed to read pk file");
    let settings_file = std::fs::read(SETTINGS_PATH).expect("Failed to read settings file");
    let settings = String::from_utf8(settings_file).expect("Failed to parse settings file");

    // 2. Call the gen_witness_wrapper function
    let witness = ios_ezkl::gen_witness_wrapper(
        input_json.to_string(),
        compiled_circuit.clone(),
        vk.clone(),
        srs.clone(),
    )
    .await;

    // 3. Assert that witness generation was successful
    assert!(witness.is_ok(), "Witness generation failed: {:?}", witness);
    let witness = witness.unwrap();

    // 4. Generate proof using prove_wrapper
    let proof = ios_ezkl::prove_wrapper(witness, compiled_circuit, pk, srs.clone());

    // 5. Assert that proof generation was successful
    assert!(proof.is_ok(), "Proof generation failed: {:?}", proof);
    let proof_json = proof.unwrap();

    // 6. Verify proof using verify_wrapper
    let verify_result = ios_ezkl::verify_wrapper(proof_json.to_string(), settings, vk, srs);

    // 7. Assert that proof verification was successful
    assert!(
        verify_result.is_ok(),
        "Proof verification failed: {:?}",
        verify_result
    );
}
