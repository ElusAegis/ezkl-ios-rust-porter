use crate::serialization::{deserialize_circuit, deserialize_params_prover, deserialize_vk};
use crate::EZKLError;
use colored_json::ToColoredJson;
use ezkl::circuit::region::RegionSettings;
use ezkl::graph::input::GraphData;
use ezkl::graph::{GraphCircuit, GraphWitness};
use ezkl::{Commitments, EZKLError as InnerEZKLError};
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use std::time::Instant;
use uniffi::deps::log::{debug, trace, warn};
use uniffi::export;

/// Generate a witness for a given circuit and input data.
/// Witness is then used to generate a proof.
///
/// # Arguments
/// input_json: String - JSON string representing the input data for the circuit.
/// compiled_circuit: Vec<Bytes> - Compiled circuit binary.
/// vk: Vec<Bytes> - Verification key binary.
/// srs: Vec<Bytes> - Structured reference string binary.
#[export]
pub async fn gen_witness_wrapper(
    input_json: String,
    compiled_circuit: Vec<u8>,
    vk: Vec<u8>,
    srs: Vec<u8>,
) -> Result<String, EZKLError> {
    // Call `gen_witness`
    let witness = gen_witness(&compiled_circuit, input_json, Some(&vk), Some(&srs)).await;

    match witness {
        Ok(graph) => graph.as_json().map_err(|e| e.into()),
        Err(e) => Err(e),
    }
    .map_err(|e| e.into())
}

pub async fn gen_witness(
    compiled_circuit: &[u8],
    input_data: String,
    serialised_vk: Option<&[u8]>,
    serialised_srs: Option<&[u8]>,
) -> Result<GraphWitness, InnerEZKLError> {
    // these aren't real values so the sanity checks are mostly meaningless

    let mut circuit = deserialize_circuit(&compiled_circuit)?;
    let data: GraphData = serde_json::from_str(&input_data)?;
    let settings = circuit.settings().clone();

    let vk = if let Some(vk) = serialised_vk {
        Some(deserialize_vk::<KZGCommitmentScheme<Bn256>, GraphCircuit>(
            vk,
            settings.clone(),
        )?)
    } else {
        None
    };

    let mut input = circuit.load_graph_input(&data).await?;

    // if any of the settings have kzg visibility then we need to load the srs

    let region_settings = RegionSettings::all_true();

    let start_time = Instant::now();
    let witness = if settings.module_requires_polycommit() {
        if serialised_srs.is_some() {
            match Commitments::from(settings.run_args.commitment) {
                Commitments::KZG => {
                    let srs: ParamsKZG<Bn256> = deserialize_params_prover::<
                        KZGCommitmentScheme<Bn256>,
                    >(
                        serialised_srs, settings.run_args.logrows
                    )?;
                    circuit.forward::<KZGCommitmentScheme<_>>(
                        &mut input,
                        vk.as_ref(),
                        Some(&srs),
                        region_settings,
                    )?
                }
                Commitments::IPA => {
                    let srs: ParamsIPA<G1Affine> = deserialize_params_prover::<
                        IPACommitmentScheme<G1Affine>,
                    >(
                        serialised_srs, settings.run_args.logrows
                    )?;
                    circuit.forward::<IPACommitmentScheme<_>>(
                        &mut input,
                        vk.as_ref(),
                        Some(&srs),
                        region_settings,
                    )?
                }
            }
        } else {
            warn!("SRS for poly commit does not exist (will be ignored)");
            circuit.forward::<KZGCommitmentScheme<Bn256>>(
                &mut input,
                vk.as_ref(),
                None,
                region_settings,
            )?
        }
    } else {
        circuit.forward::<KZGCommitmentScheme<Bn256>>(
            &mut input,
            vk.as_ref(),
            None,
            region_settings,
        )?
    };

    // print each variable tuple (symbol, value) as symbol=value
    trace!(
        "witness generation {:?} took {:?}",
        circuit
            .settings()
            .run_args
            .variables
            .iter()
            .map(|v| { format!("{}={}", v.0, v.1) })
            .collect::<Vec<_>>(),
        start_time.elapsed()
    );

    // print the witness in debug
    debug!("witness: \n {}", witness.as_json()?.to_colored_json_auto()?);

    Ok(witness)
}
