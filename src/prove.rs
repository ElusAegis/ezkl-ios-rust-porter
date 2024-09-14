use crate::util::{
    deserialize_params_prover, EZKLError, IPAAccumulatorStrategy, IPASingleStrategy,
    KZGAccumulatorStrategy, KZGSingleStrategy,
};
use ezkl::circuit::CheckMode;
use ezkl::graph::{GraphCircuit, GraphWitness};
use ezkl::pfsys::evm::aggregation_kzg::PoseidonTranscript;
use ezkl::pfsys::{
    create_proof_circuit, load_pk, ProofSplitCommit, ProofType, Snark, StrategyType, TranscriptType,
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
use std::path::PathBuf;
use uniffi::export;

/// Proves a circuit with the given witness and parameters
/// This function is used for advanced proving configurations
/// It allows to specify the proof type and check mode
/// 1. Proof type: Single (default) or ForAggr, where Single is the default mode, and ForAggr is used for proof aggregation
/// 2. Check mode: SAFE (default) or UNSAFE, where SAFE is the default mode, and UNSAFE is used for debugging purposes
#[export]
pub fn prove_advanced_wrapper(
    witness_json: String,
    compiled_circuit_path: String,
    pk_path: String,
    serialised_srs: Vec<u8>,
    proof_type: ProofTypeWrapper,
    check_mode: CheckModeWrapper,
) -> Result<String, EZKLError> {
    let compiled_circuit_path = PathBuf::from(compiled_circuit_path);
    let pk_path = PathBuf::from(pk_path);
    let proof_type = proof_type.into();
    let check_mode = check_mode.into();

    let proof = prove(
        Some(witness_json),
        None,
        compiled_circuit_path,
        pk_path,
        Some(&serialised_srs),
        proof_type,
        check_mode,
    );

    match proof {
        Ok(snark) => serde_json::to_string(&snark).map_err(|e| e.into()),
        Err(e) => Err(e),
    }
    .map_err(|e| e.into())
}

/// Proves a circuit with the given witness and parameters
/// This function is used for default proving configurations to abstract the configuration details
#[export]
pub fn prove_wrapper(
    witness_json: String,
    compiled_circuit_path: String,
    pk_path: String,
    serialised_srs: Vec<u8>,
) -> Result<String, EZKLError> {
    prove_advanced_wrapper(
        witness_json,
        compiled_circuit_path,
        pk_path,
        serialised_srs,
        ProofTypeWrapper::Single,
        CheckModeWrapper::SAFE,
    )
}

pub(crate) fn prove(
    witness_json: Option<String>,
    witness_path: Option<PathBuf>,
    compiled_circuit_path: PathBuf, // bincode::deserialize_from
    pk_path: PathBuf,               // byte vector reader
    serialised_srs: Option<&[u8]>,
    proof_type: ProofType,
    check_mode: CheckMode,
) -> Result<Snark<Fr, G1Affine>, InnerEZKLError> {
    let data = match (witness_json, witness_path) {
        (Some(json), None) => serde_json::from_str(&json)?,
        (None, Some(path)) => GraphWitness::from_path(path)?,
        _ => {
            return Err(InnerEZKLError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Witness must be provided in one of the two ways: json or path",
            )))
        }
    };

    let mut circuit = GraphCircuit::load(compiled_circuit_path)?;

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
            let pk =
                load_pk::<KZGCommitmentScheme<Bn256>, GraphCircuit>(pk_path, circuit.params())?;

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
            let pk =
                load_pk::<IPACommitmentScheme<G1Affine>, GraphCircuit>(pk_path, circuit.params())?;

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
