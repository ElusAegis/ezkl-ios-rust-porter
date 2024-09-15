use crate::serialization::{deserialize_params_verifier, deserialize_vk};
use crate::{ExternalEZKLError, IPASingleStrategy, KZGSingleStrategy};
use ezkl::graph::{GraphCircuit, GraphSettings};
use ezkl::pfsys::evm::aggregation_kzg::PoseidonTranscript;
use ezkl::pfsys::{verify_proof_circuit, Snark, TranscriptType};
use ezkl::{Commitments, EZKLError as InnerEZKLError};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::halo2curves::ff::{FromUniformBytes, WithSmallOrderMulGroup};
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::plonk;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::poly::commitment::{CommitmentScheme, Verifier};
use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_proofs::poly::ipa::multiopen::VerifierIPA;
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_proofs::poly::VerificationStrategy;
use halo2_proofs::transcript::{EncodedChallenge, TranscriptReadBuffer};
use serde::de::DeserializeOwned;
use serde::Serialize;
use snark_verifier::loader::native::NativeLoader;
use snark_verifier::system::halo2::transcript::evm::EvmTranscript;
use std::io::Cursor;
use std::time::Instant;
use uniffi::deps::log::info;
use uniffi::export;

/// Verify a proof with the given parameters
///
/// # Arguments
/// proof_json: String - JSON string representing the proof to be verified.
/// settings_json: String - JSON string representing the settings for the circuit.
/// vk: Vec<Bytes> - Verification key binary.
/// srs: Vec<Bytes> - Structured reference string binary.
#[export]
pub fn verify_wrapper(
    proof_json: String,
    settings_json: String,
    vk: Vec<u8>,
    srs: Vec<u8>,
) -> Result<bool, ExternalEZKLError> {
    verify(proof_json, settings_json, &vk, Some(&srs), false).map_err(|e| e.into())
}

pub(crate) fn verify(
    proof_json: String,
    settings_json: String,
    serialised_vk: &[u8],
    serialised_srs: Option<&[u8]>,
    reduced_srs: bool,
) -> Result<bool, InnerEZKLError> {
    let circuit_settings = GraphSettings::from_json(&settings_json)?;

    let logrows = circuit_settings.run_args.logrows;
    let commitment = circuit_settings.run_args.commitment.into();

    match commitment {
        Commitments::KZG => {
            let proof: Snark<Fr, G1Affine> = serde_json::from_str(&proof_json)?;

            //     (None, Some(proof_path)) => Snark::load::<KZGCommitmentScheme<Bn256>>(&proof_path),
            //     (Some(proof_json), None) => Ok(serde_json::from_str(proof_json)?),
            //     _ => {
            //         return Err(InnerEZKLError::IoError(std::io::Error::new(
            //             std::io::ErrorKind::InvalidInput,
            //             "Proof must be provided in one of the two ways: json or path",
            //         )))
            //     }
            // }?;
            let params: ParamsKZG<Bn256> = if reduced_srs {
                // only need G_0 for the verification with shplonk
                deserialize_params_verifier::<KZGCommitmentScheme<Bn256>>(serialised_srs, 1)?
            } else {
                deserialize_params_verifier::<KZGCommitmentScheme<Bn256>>(serialised_srs, logrows)?
            };
            match proof.transcript_type {
                TranscriptType::EVM => verify_commitment::<
                    KZGCommitmentScheme<Bn256>,
                    VerifierSHPLONK<'_, Bn256>,
                    _,
                    KZGSingleStrategy<_>,
                    EvmTranscript<G1Affine, _, _, _>,
                    GraphCircuit,
                    _,
                >(
                    proof_json,
                    circuit_settings,
                    serialised_vk,
                    &params,
                    logrows,
                ),
                TranscriptType::Poseidon => verify_commitment::<
                    KZGCommitmentScheme<Bn256>,
                    VerifierSHPLONK<'_, Bn256>,
                    _,
                    KZGSingleStrategy<_>,
                    PoseidonTranscript<NativeLoader, _>,
                    GraphCircuit,
                    _,
                >(
                    proof_json,
                    circuit_settings,
                    serialised_vk,
                    &params,
                    logrows,
                ),
            }
        }
        Commitments::IPA => {
            let proof: Snark<Fr, G1Affine> = serde_json::from_str(&proof_json)?;

            let params: ParamsIPA<_> = deserialize_params_verifier::<IPACommitmentScheme<G1Affine>>(
                serialised_srs,
                logrows,
            )?;
            match proof.transcript_type {
                TranscriptType::EVM => verify_commitment::<
                    IPACommitmentScheme<G1Affine>,
                    VerifierIPA<_>,
                    _,
                    IPASingleStrategy<_>,
                    EvmTranscript<G1Affine, _, _, _>,
                    GraphCircuit,
                    _,
                >(
                    proof_json,
                    circuit_settings,
                    serialised_vk,
                    &params,
                    logrows,
                ),
                TranscriptType::Poseidon => verify_commitment::<
                    IPACommitmentScheme<G1Affine>,
                    VerifierIPA<_>,
                    _,
                    IPASingleStrategy<_>,
                    PoseidonTranscript<NativeLoader, _>,
                    GraphCircuit,
                    _,
                >(
                    proof_json,
                    circuit_settings,
                    serialised_vk,
                    &params,
                    logrows,
                ),
            }
        }
    }
}

fn verify_commitment<
    'a,
    Scheme: CommitmentScheme,
    V: Verifier<'a, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    Strategy: VerificationStrategy<'a, Scheme, V>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, Scheme::Curve, E>,
    C: Circuit<<Scheme as CommitmentScheme>::Scalar, Params = Params>,
    Params,
>(
    proof_json: String,
    settings: Params,
    serialized_vk: &[u8],
    params: &'a Scheme::ParamsVerifier,
    logrows: u32,
) -> Result<bool, InnerEZKLError>
where
    Scheme::Scalar: FromUniformBytes<64>
        + SerdeObject
        + Serialize
        + DeserializeOwned
        + WithSmallOrderMulGroup<3>,
    Scheme::Curve: SerdeObject + Serialize + DeserializeOwned,
    Scheme::ParamsVerifier: 'a,
{
    let proof: Snark<Scheme::Scalar, Scheme::Curve> = serde_json::from_str(&proof_json)?;

    let strategy = Strategy::new(params);
    let vk = deserialize_vk::<Scheme, C>(serialized_vk, settings)?;
    let now = Instant::now();

    let result =
        verify_proof_circuit::<V, _, _, _, TR>(&proof, params, &vk, strategy, 1 << logrows);

    let elapsed = now.elapsed();
    info!(
        "verify took {}.{}",
        elapsed.as_secs(),
        elapsed.subsec_millis()
    );
    info!("verified: {}", result.is_ok());
    result.map_err(|e: plonk::Error| e.into()).map(|_| true)
}
