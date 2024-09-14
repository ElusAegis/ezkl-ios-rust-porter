use crate::util::KZGSingleStrategy;
use crate::util::{EZKLError, IPASingleStrategy};
use ezkl::graph::{GraphCircuit, GraphSettings};
use ezkl::pfsys::evm::aggregation_kzg::PoseidonTranscript;
use ezkl::pfsys::srs::load_srs_verifier;
use ezkl::pfsys::{load_vk, verify_proof_circuit, Snark, TranscriptType};
use ezkl::{Commitments, EZKLError as InnerEZKLError};
use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
use halo2_proofs::halo2curves::ff::{FromUniformBytes, WithSmallOrderMulGroup};
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::plonk;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::poly::commitment::{CommitmentScheme, Params, Verifier};
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
use std::path::PathBuf;
use std::time::Instant;
use uniffi::deps::log::info;
use uniffi::export;

#[export]
pub fn verify_wrapper(
    proof_json: String,
    settings_path: String,
    vk_path: String,
    srs_path: Option<String>,
) -> Result<bool, EZKLError> {
    let settings_path = PathBuf::from(settings_path);
    let vk_path = PathBuf::from(vk_path);
    let srs_path = srs_path.map(PathBuf::from);

    verify(
        Some(proof_json),
        None,
        settings_path,
        vk_path,
        srs_path,
        false,
    )
    .map_err(|e| e.into())
}

pub(crate) fn verify(
    proof_json: Option<String>,
    proof_path: Option<PathBuf>,
    settings_path: PathBuf,    // JSON
    vk_path: PathBuf,          // byte vector reader
    srs_path: Option<PathBuf>, // byte vector reader
    reduced_srs: bool,
) -> Result<bool, InnerEZKLError> {
    let circuit_settings = GraphSettings::load(&settings_path)?;

    let logrows = circuit_settings.run_args.logrows;
    let commitment = circuit_settings.run_args.commitment.into();

    match commitment {
        Commitments::KZG => {
            let proof = match (&proof_json, &proof_path) {
                (None, Some(proof_path)) => Snark::load::<KZGCommitmentScheme<Bn256>>(&proof_path),
                (Some(proof_json), None) => Ok(serde_json::from_str(proof_json)?),
                _ => {
                    return Err(InnerEZKLError::IoError(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Proof must be provided in one of the two ways: json or path",
                    )))
                }
            }?;
            let params: ParamsKZG<Bn256> = if reduced_srs {
                // only need G_0 for the verification with shplonk
                load_params_verifier::<KZGCommitmentScheme<Bn256>>(srs_path, 1)?
            } else {
                load_params_verifier::<KZGCommitmentScheme<Bn256>>(srs_path, logrows)?
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
                    proof_path,
                    circuit_settings,
                    vk_path,
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
                    proof_path,
                    circuit_settings,
                    vk_path,
                    &params,
                    logrows,
                ),
            }
        }
        Commitments::IPA => {
            let proof = match (&proof_json, &proof_path) {
                (None, Some(proof_path)) => {
                    Snark::load::<IPACommitmentScheme<G1Affine>>(&proof_path)
                }
                (Some(proof_json), None) => Ok(serde_json::from_str(proof_json)?),
                _ => {
                    return Err(InnerEZKLError::IoError(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Proof must be provided in one of the two ways: json or path",
                    )))
                }
            }?;
            let params: ParamsIPA<_> =
                load_params_verifier::<IPACommitmentScheme<G1Affine>>(srs_path, logrows)?;
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
                    proof_path,
                    circuit_settings,
                    vk_path,
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
                    proof_path,
                    circuit_settings,
                    vk_path,
                    &params,
                    logrows,
                ),
            }
        }
    }
}

fn load_params_verifier<Scheme: CommitmentScheme>(
    srs_path: Option<PathBuf>,
    logrows: u32,
) -> Result<Scheme::ParamsVerifier, InnerEZKLError> {
    let srs_path = srs_path.ok_or(InnerEZKLError::IoError(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "SRS path must be provided",
    )))?;
    let mut params = load_srs_verifier::<Scheme>(srs_path)?;
    if logrows < params.k() {
        info!("downsizing params to {} logrows", logrows);
        params.downsize(logrows);
    }
    Ok(params)
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
    proof_json: Option<String>,
    proof_path: Option<PathBuf>,
    settings: Params,
    vk_path: PathBuf,
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
    let proof = match (proof_json, proof_path) {
        (None, Some(proof_path)) => Snark::load::<Scheme>(&proof_path),
        (Some(proof_json), None) => Ok(serde_json::from_str(&proof_json)?),
        _ => {
            return Err(InnerEZKLError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Proof must be provided in one of the two ways: json or path",
            )))
        }
    }?;

    let strategy = Strategy::new(params);
    let vk = load_vk::<Scheme, C>(vk_path, settings)?;
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
