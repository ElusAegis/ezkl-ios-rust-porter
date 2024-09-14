use crate::InnerEZKLError;
use ezkl::graph::GraphCircuit;
use ezkl::pfsys::srs::SrsError;
use ezkl::pfsys::PfsysError;
use ezkl::EZKL_BUF_CAPACITY;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::ff::{FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::plonk::{Circuit, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::{CommitmentScheme, Params};
use halo2_proofs::SerdeFormat::RawBytes;
use std::io::BufReader;
use uniffi::deps::log::{debug, info};

pub(crate) fn deserialize_circuit(compiled_circuit: &[u8]) -> Result<GraphCircuit, InnerEZKLError> {
    let circuit: GraphCircuit = bincode::deserialize(&compiled_circuit).map_err(|e| {
        ezkl::EZKLError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    })?;
    Ok(circuit)
}

/// Deserialize a verification key from a byte vector.
/// Currently only supports `RawBytes` format, which is the EZKL default format.
/// TODO - consider allowing other formats.
pub(crate) fn deserialize_vk<Scheme: CommitmentScheme, C: Circuit<Scheme::Scalar>>(
    serialised_vk: &[u8],
    params: <C as Circuit<Scheme::Scalar>>::Params,
) -> Result<VerifyingKey<Scheme::Curve>, PfsysError>
where
    C: Circuit<Scheme::Scalar>,
    Scheme::Curve: SerdeObject + CurveAffine,
    Scheme::Scalar: PrimeField + SerdeObject + FromUniformBytes<64>,
{
    debug!("deserializing verification key...");
    let cursor = std::io::Cursor::new(serialised_vk);
    let mut reader = BufReader::with_capacity(*EZKL_BUF_CAPACITY, cursor);
    let vk = VerifyingKey::<Scheme::Curve>::read::<_, C>(
        &mut reader,
        RawBytes, // TODO - consider allowing other formats
        params,
    )
    .map_err(|e| PfsysError::LoadVk(format!("{}", e)))?;
    info!("deserialized verification key ✅");
    Ok(vk)
}

/// Deserialize a proving key from a byte vector.
/// Currently only supports `RawBytes` format, which is the EZKL default format.
/// TODO - consider allowing other formats.
pub(crate) fn deserialize_pk<Scheme: CommitmentScheme, C: Circuit<Scheme::Scalar>>(
    serialised_pk: &[u8],
    params: <C as Circuit<Scheme::Scalar>>::Params,
) -> Result<ProvingKey<Scheme::Curve>, PfsysError>
where
    C: Circuit<Scheme::Scalar>,
    Scheme::Curve: SerdeObject + CurveAffine,
    Scheme::Scalar: PrimeField + SerdeObject + FromUniformBytes<64>,
{
    debug!("deserializing proving key...");
    let cursor = std::io::Cursor::new(serialised_pk);
    let mut reader = BufReader::with_capacity(*EZKL_BUF_CAPACITY, cursor);
    let pk = ProvingKey::<Scheme::Curve>::read::<_, C>(
        &mut reader,
        RawBytes, // TODO - consider allowing other formats
        params,
    )
    .map_err(|e| PfsysError::LoadPk(format!("{}", e)))?;
    info!("loaded proving key ✅");
    Ok(pk)
}

pub fn deserialize_params_prover<Scheme: CommitmentScheme>(
    serialized_srs: Option<&[u8]>,
    logrows: u32,
) -> Result<Scheme::ParamsProver, InnerEZKLError> {
    let serialized_srs = serialized_srs.ok_or(InnerEZKLError::IoError(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "SRS must be provided",
    )))?;

    let cursor = std::io::Cursor::new(serialized_srs);
    let mut reader = BufReader::new(cursor);
    let mut params: Scheme::ParamsProver = Params::<'_, Scheme::Curve>::read(&mut reader)
        .map_err(|e| SrsError::ReadError(e.to_string()))?;
    if logrows < params.k() {
        info!("downsizing params to {} logrows", logrows);
        params.downsize(logrows);
    }
    Ok(params)
}

pub(crate) fn deserialize_params_verifier<Scheme: CommitmentScheme>(
    serialized_srs: Option<&[u8]>,
    logrows: u32,
) -> Result<Scheme::ParamsVerifier, InnerEZKLError> {
    let serialized_srs = serialized_srs.ok_or(InnerEZKLError::IoError(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "SRS must be provided",
    )))?;
    let cursor = std::io::Cursor::new(serialized_srs);
    let mut reader = BufReader::new(cursor);
    let mut params: Scheme::ParamsVerifier = Params::<'_, Scheme::Curve>::read(&mut reader)
        .map_err(|e| SrsError::ReadError(e.to_string()))?;
    if logrows < params.k() {
        info!("downsizing params to {} logrows", logrows);
        params.downsize(logrows);
    }
    Ok(params)
}
