use crate::serialization::{deserialize_circuit, deserialize_params_prover, deserialize_pk};
use crate::ExternalEZKLError;
use crate::{IPAAccumulatorStrategy, IPASingleStrategy, KZGAccumulatorStrategy, KZGSingleStrategy};
use ezkl::circuit::CheckMode;
use ezkl::graph::{GraphCircuit, GraphWitness};
use ezkl::pfsys::evm::aggregation_kzg::PoseidonTranscript;
use ezkl::pfsys::{
    create_proof_circuit, ProofSplitCommit, ProofType, Snark, StrategyType, TranscriptType,
};
use ezkl::{Commitments, EZKLError as InnerEZKLError};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::plonk::Circuit;
use halo2_proofs::poly::ipa::commitment::IPACommitmentScheme;
use halo2_proofs::poly::ipa::multiopen::{ProverIPA, VerifierIPA};
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use snark_verifier::loader::native::NativeLoader;
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use snark_verifier::system::halo2::{compile, Config};
use uniffi::export;

/// Proves a circuit using the provided witness, compiled circuit, proving key, and SRS.
///
/// This function abstracts away configuration details by using default proving configurations.
///
/// # Arguments
///
/// * `witness_json` - A `String` containing the JSON representation of the witness generated for the circuit input.
/// * `compiled_circuit` - A `Vec<u8>` containing the compiled circuit in binary form.
/// * `pk` - A `Vec<u8>` containing the Proving Key (PK) in binary form.
/// * `srs` - A `Vec<u8>` containing the Structured Reference String (SRS) in binary form.
///
/// # Returns
///
/// * `Ok(String)` - The generated proof as a JSON `String`.
/// * `Err(ExternalEZKLError)` - An error that occurred during the proving process.
#[export]
pub fn prove(
    witness_json: String,
    compiled_circuit: Vec<u8>,
    pk: Vec<u8>,
    srs: Vec<u8>,
) -> Result<String, ExternalEZKLError> {
    prove_advanced(
        witness_json,
        compiled_circuit,
        pk,
        srs,
        ProofTypeWrapper::Single,
        CheckModeWrapper::SAFE,
    )
}

/// Proves a circuit using the provided witness, compiled circuit, proving key, and SRS.
///
/// This function is used for advanced proving configurations.
///
/// # Arguments
///
/// * `witness_json` - A `String` containing the JSON representation of the witness generated for the circuit input.
/// * `compiled_circuit` - A `Vec<u8>` containing the compiled circuit in binary form.
/// * `pk` - A `Vec<u8>` containing the Proving Key (PK) in binary form.
/// * `srs` - A `Vec<u8>` containing the Structured Reference String (SRS) in binary form.
/// * `proof_type` - A `ProofTypeWrapper` enum value representing the proof type to be used for proving. Default is `Single`. For aggregation proofs, use `ForAggr`.
/// * `check_mode` - A `CheckModeWrapper` enum value representing the check mode to be used for proving. Default is `SAFE`. For unsafe proving useful for debugging, use `UNSAFE`.
///
/// # Returns
///
/// * `Ok(String)` - The generated proof as a JSON `String`.
/// * `Err(ExternalEZKLError)` - An error that occurred during the proving process.
#[export]
pub fn prove_advanced(
    witness_json: String,
    compiled_circuit: Vec<u8>,
    pk: Vec<u8>,
    srs: Vec<u8>,
    proof_type: ProofTypeWrapper,
    check_mode: CheckModeWrapper,
) -> Result<String, ExternalEZKLError> {
    let proof = prove_internal(
        witness_json,
        &compiled_circuit,
        &pk,
        Some(&srs),
        proof_type.into(),
        check_mode.into(),
    );

    match proof {
        Ok(snark) => serde_json::to_string(&snark).map_err(|e| e.into()),
        Err(e) => Err(e),
    }
    .map_err(|e| e.into())
}

pub(crate) fn prove_internal(
    witness_json: String,
    compiled_circuit: &[u8],
    serialized_pk: &[u8],
    serialised_srs: Option<&[u8]>,
    proof_type: ProofType,
    check_mode: CheckMode,
) -> Result<Snark<Fr, G1Affine>, InnerEZKLError> {
    let data: GraphWitness = serde_json::from_str(&witness_json)?;
    //
    // match (witness_json, witness_path) {
    //     (Some(json), None) =>
    //     (None, Some(path)) => GraphWitness::from_path(path)?,
    //     _ => {
    //         return Err(InnerEZKLError::IoError(std::io::Error::new(
    //             std::io::ErrorKind::InvalidInput,
    //             "Witness must be provided in one of the two ways: json or path",
    //         )))
    //     }
    // };

    let mut circuit: GraphCircuit = deserialize_circuit(compiled_circuit)?;

    circuit.load_graph_witness(&data)?;

    let pretty_public_inputs = circuit.pretty_public_inputs(&data)?;
    let public_inputs = circuit.prepare_public_inputs(&data)?;

    let circuit_settings = circuit.settings().clone();

    let strategy: StrategyType = proof_type.into();
    let transcript: TranscriptType = proof_type.into();
    let proof_split_commits: Option<ProofSplitCommit> = data.into();

    let commitment = circuit_settings.run_args.commitment.into();
    let logrows = circuit_settings.run_args.logrows;
    // creates and verifies the proof
    let mut snark = match commitment {
        Commitments::KZG => {
            let pk = deserialize_pk::<KZGCommitmentScheme<Bn256>, GraphCircuit>(
                serialized_pk,
                circuit.params(),
            )?;

            let params =
                deserialize_params_prover::<KZGCommitmentScheme<Bn256>>(serialised_srs, logrows)?;
            match strategy {
                StrategyType::Single => create_proof_circuit::<
                    KZGCommitmentScheme<Bn256>,
                    _,
                    ProverSHPLONK<_>,
                    VerifierSHPLONK<_>,
                    KZGSingleStrategy<_>,
                    _,
                    EvmTranscript<_, _, _, _>,
                    EvmTranscript<_, _, _, _>,
                >(
                    circuit,
                    vec![public_inputs],
                    &params,
                    &pk,
                    check_mode,
                    commitment,
                    transcript,
                    proof_split_commits,
                    None,
                ),
                StrategyType::Accum => {
                    let protocol = Some(compile(
                        &params,
                        pk.get_vk(),
                        Config::kzg().with_num_instance(vec![public_inputs.len()]),
                    ));

                    create_proof_circuit::<
                        KZGCommitmentScheme<Bn256>,
                        _,
                        ProverSHPLONK<_>,
                        VerifierSHPLONK<_>,
                        KZGAccumulatorStrategy<_>,
                        _,
                        PoseidonTranscript<NativeLoader, _>,
                        PoseidonTranscript<NativeLoader, _>,
                    >(
                        circuit,
                        vec![public_inputs],
                        &params,
                        &pk,
                        check_mode,
                        commitment,
                        transcript,
                        proof_split_commits,
                        protocol,
                    )
                }
            }
        }
        Commitments::IPA => {
            let pk = deserialize_pk::<IPACommitmentScheme<G1Affine>, GraphCircuit>(
                serialized_pk,
                circuit.params(),
            )?;

            let params = deserialize_params_prover::<IPACommitmentScheme<G1Affine>>(
                serialised_srs,
                circuit_settings.run_args.logrows,
            )?;
            match strategy {
                StrategyType::Single => create_proof_circuit::<
                    IPACommitmentScheme<G1Affine>,
                    _,
                    ProverIPA<_>,
                    VerifierIPA<_>,
                    IPASingleStrategy<_>,
                    _,
                    EvmTranscript<_, _, _, _>,
                    EvmTranscript<_, _, _, _>,
                >(
                    circuit,
                    vec![public_inputs],
                    &params,
                    &pk,
                    check_mode,
                    commitment,
                    transcript,
                    proof_split_commits,
                    None,
                ),
                StrategyType::Accum => {
                    let protocol = Some(compile(
                        &params,
                        pk.get_vk(),
                        Config::ipa().with_num_instance(vec![public_inputs.len()]),
                    ));
                    create_proof_circuit::<
                        IPACommitmentScheme<G1Affine>,
                        _,
                        ProverIPA<_>,
                        VerifierIPA<_>,
                        IPAAccumulatorStrategy<_>,
                        _,
                        PoseidonTranscript<NativeLoader, _>,
                        PoseidonTranscript<NativeLoader, _>,
                    >(
                        circuit,
                        vec![public_inputs],
                        &params,
                        &pk,
                        check_mode,
                        commitment,
                        transcript,
                        proof_split_commits,
                        protocol,
                    )
                }
            }
        }
    }?;

    snark.pretty_public_inputs = pretty_public_inputs;

    // if let Some(proof_path) = proof_path {
    //     snark.save(&proof_path)?;
    // }

    Ok(snark)
}

#[derive(uniffi::Enum)]
pub enum ProofTypeWrapper {
    // Single is the default mode, should mostly be used for production
    Single,
    ForAggr,
}

impl From<ProofTypeWrapper> for ProofType {
    fn from(pt: ProofTypeWrapper) -> Self {
        match pt {
            ProofTypeWrapper::Single => ProofType::Single,
            ProofTypeWrapper::ForAggr => ProofType::ForAggr,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(uniffi::Enum)]
pub enum CheckModeWrapper {
    // SAFE is the default mode, should be always used for production
    SAFE,
    UNSAFE,
}

impl From<CheckModeWrapper> for CheckMode {
    fn from(cm: CheckModeWrapper) -> Self {
        match cm {
            CheckModeWrapper::SAFE => CheckMode::SAFE,
            CheckModeWrapper::UNSAFE => CheckMode::UNSAFE,
        }
    }
}
