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

/// Deserializes a compiled circuit from a byte slice.
///
/// # Arguments
///
/// * `compiled_circuit` - A byte slice containing the serialized circuit.
///
/// # Returns
///
/// * `Ok(GraphCircuit)` - The deserialized circuit.
/// * `Err(InnerEZKLError)` - If deserialization fails.
pub(crate) fn deserialize_circuit(compiled_circuit: &[u8]) -> Result<GraphCircuit, InnerEZKLError> {
    // Deserialize the circuit using `bincode`
    let circuit: GraphCircuit = bincode::deserialize(compiled_circuit).map_err(|e| {
        ezkl::EZKLError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    })?;
    Ok(circuit)
}

/// Deserializes a verification key from a byte slice.
///
/// Currently only supports `RawBytes` format, which is the EZKL default format.
///
/// # Arguments
///
/// * `serialised_vk` - A byte slice containing the serialized verification key.
/// * `params` - Circuit parameters required for deserialization.
///
/// # Returns
///
/// * `Ok(VerifyingKey<Scheme::Curve>)` - The deserialized verification key.
/// * `Err(PfsysError)` - If deserialization fails.
pub(crate) fn deserialize_vk<Scheme: CommitmentScheme, C>(
    serialised_vk: &[u8],
    params: <C as Circuit<Scheme::Scalar>>::Params,
) -> Result<VerifyingKey<Scheme::Curve>, PfsysError>
where
    C: Circuit<Scheme::Scalar>,
    Scheme::Curve: SerdeObject + CurveAffine,
    Scheme::Scalar: PrimeField + SerdeObject + FromUniformBytes<64>,
{
    debug!("Deserializing verification key...");
    // Create a buffered reader over the serialized verification key
    let cursor = std::io::Cursor::new(serialised_vk);
    let mut reader = BufReader::with_capacity(*EZKL_BUF_CAPACITY, cursor);
    // Read the verification key from the buffer
    let vk = VerifyingKey::<Scheme::Curve>::read::<_, C>(
        &mut reader,
        RawBytes, // Currently only supports RawBytes format
        params,
    )
    .map_err(|e| PfsysError::LoadVk(format!("{}", e)))?;
    info!("Deserialized verification key");
    Ok(vk)
}

/// Deserializes a proving key from a byte slice.
///
/// Currently only supports `RawBytes` format, which is the EZKL default format.
///
/// # Arguments
///
/// * `serialised_pk` - A byte slice containing the serialized proving key.
/// * `params` - Circuit parameters required for deserialization.
///
/// # Returns
///
/// * `Ok(ProvingKey<Scheme::Curve>)` - The deserialized proving key.
/// * `Err(PfsysError)` - If deserialization fails.
pub(crate) fn deserialize_pk<Scheme: CommitmentScheme, C>(
    serialised_pk: &[u8],
    params: <C as Circuit<Scheme::Scalar>>::Params,
) -> Result<ProvingKey<Scheme::Curve>, PfsysError>
where
    C: Circuit<Scheme::Scalar>,
    Scheme::Curve: SerdeObject + CurveAffine,
    Scheme::Scalar: PrimeField + SerdeObject + FromUniformBytes<64>,
{
    debug!("Deserializing proving key...");
    // Create a buffered reader over the serialized proving key
    let cursor = std::io::Cursor::new(serialised_pk);
    let mut reader = BufReader::with_capacity(*EZKL_BUF_CAPACITY, cursor);
    // Read the proving key from the buffer
    let pk = ProvingKey::<Scheme::Curve>::read::<_, C>(
        &mut reader,
        RawBytes, // Currently only supports RawBytes format
        params,
    )
    .map_err(|e| PfsysError::LoadPk(format!("{}", e)))?;
    info!("Loaded proving key");
    Ok(pk)
}

/// Deserializes the prover's parameters from a byte slice.
///
/// # Arguments
///
/// * `serialized_srs` - An optional byte slice containing the serialized SRS (structured reference string).
/// * `logrows` - The desired number of rows as a power of two (log₂ of the number of rows).
///
/// # Returns
///
/// * `Ok(Scheme::ParamsProver)` - The deserialized prover parameters.
/// * `Err(InnerEZKLError)` - If the SRS is not provided or deserialization fails.
pub fn deserialize_params_prover<Scheme: CommitmentScheme>(
    serialized_srs: Option<&[u8]>,
    logrows: u32,
) -> Result<Scheme::ParamsProver, InnerEZKLError> {
    // Ensure the SRS is provided
    let serialized_srs = serialized_srs.ok_or_else(|| {
        InnerEZKLError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SRS must be provided",
        ))
    })?;

    // Create a buffered reader over the serialized SRS
    let cursor = std::io::Cursor::new(serialized_srs);
    let mut reader = BufReader::new(cursor);
    // Read the parameters from the buffer
    let mut params: Scheme::ParamsProver = Params::<'_, Scheme::Curve>::read(&mut reader)
        .map_err(|e| SrsError::ReadError(e.to_string()))?;
    // Downsize the parameters if necessary
    if logrows < params.k() {
        info!("Downsizing params to {} logrows", logrows);
        params.downsize(logrows);
    }
    Ok(params)
}

/// Deserializes the verifier's parameters from a byte slice.
///
/// # Arguments
///
/// * `serialized_srs` - An optional byte slice containing the serialized SRS.
/// * `logrows` - The desired number of rows as a power of two (log₂ of the number of rows).
///
/// # Returns
///
/// * `Ok(Scheme::ParamsVerifier)` - The deserialized verifier parameters.
/// * `Err(InnerEZKLError)` - If the SRS is not provided or deserialization fails.
pub(crate) fn deserialize_params_verifier<Scheme: CommitmentScheme>(
    serialized_srs: Option<&[u8]>,
    logrows: u32,
) -> Result<Scheme::ParamsVerifier, InnerEZKLError> {
    // Ensure the SRS is provided
    let serialized_srs = serialized_srs.ok_or_else(|| {
        InnerEZKLError::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SRS must be provided",
        ))
    })?;

    // Create a buffered reader over the serialized SRS
    let cursor = std::io::Cursor::new(serialized_srs);
    let mut reader = BufReader::new(cursor);
    // Read the parameters from the buffer
    let mut params: Scheme::ParamsVerifier = Params::<'_, Scheme::Curve>::read(&mut reader)
        .map_err(|e| SrsError::ReadError(e.to_string()))?;
    // Downsize the parameters if necessary
    if logrows < params.k() {
        info!("Downsizing params to {} logrows", logrows);
        params.downsize(logrows);
    }
    Ok(params)
}
