use ezkl::pfsys::srs::SrsError;
use ezkl::pfsys::PfsysError;
use ezkl::{EZKLError as InnerEZKLError, EZKL_BUF_CAPACITY};
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::ff::{FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::plonk::{Circuit, VerifyingKey};
use halo2_proofs::poly::commitment::{CommitmentScheme, Params};
pub(crate) use halo2_proofs::poly::ipa::strategy::AccumulatorStrategy as IPAAccumulatorStrategy;
pub(crate) use halo2_proofs::poly::ipa::strategy::SingleStrategy as IPASingleStrategy;
pub(crate) use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy as KZGAccumulatorStrategy;
pub(crate) use halo2_proofs::poly::kzg::strategy::SingleStrategy as KZGSingleStrategy;
use halo2_proofs::SerdeFormat::RawBytes;
use std::fmt::Display;
use std::io;
use std::io::BufReader;
use uniffi::deps::log::{debug, info};

/// Deserialize a verification key from a byte vector.
/// Currently only supports `RawBytes` format, which is the EZKL default format.
/// TODO - consider allowing other formats.
pub fn deserialise_vk<Scheme: CommitmentScheme, C: Circuit<Scheme::Scalar>>(
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

pub(crate) fn deserialize_params_prover<Scheme: CommitmentScheme>(
    serialised_srs: Option<&[u8]>,
    logrows: u32,
) -> Result<Scheme::ParamsProver, InnerEZKLError> {
    let srs_path = serialised_srs.ok_or(InnerEZKLError::IoError(io::Error::new(
        io::ErrorKind::InvalidInput,
        "SRS must be provided",
    )))?;

    let cursor = std::io::Cursor::new(srs_path);
    let mut reader = BufReader::new(cursor);
    let mut params: Scheme::ParamsProver = Params::<'_, Scheme::Curve>::read(&mut reader)
        .map_err(|e| SrsError::ReadError(e.to_string()))?;
    if logrows < params.k() {
        info!("downsizing params to {} logrows", logrows);
        params.downsize(logrows);
    }
    Ok(params)
}

#[derive(uniffi::Error, Debug)]
pub enum EZKLError {
    InternalError(String),
    InvalidInput(String),
}

impl Display for EZKLError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EZKLError::InternalError(e) => write!(f, "Internal error: {}", e),
            EZKLError::InvalidInput(e) => write!(f, "Invalid input: {}", e),
        }
    }
}

impl From<InnerEZKLError> for EZKLError {
    fn from(e: InnerEZKLError) -> Self {
        EZKLError::InternalError(e.to_string())
    }
}

pub(crate) mod testing {
    use crate::util::deserialize_params_prover;
    use ezkl::graph::{GraphCircuit, GraphWitness};
    use ezkl::pfsys::{create_keys, save_pk, save_vk};
    use ezkl::Commitments;
    use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
    use halo2_proofs::poly::ipa::commitment::IPACommitmentScheme;
    use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
    use std::path::PathBuf;

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
                let params = deserialize_params_prover::<KZGCommitmentScheme<Bn256>>(
                    serialized_srs,
                    logrows,
                )?;
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
}
