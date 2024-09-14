use ezkl::pfsys::srs::load_srs_prover;
use ezkl::{EZKLError as InnerEZKLError, EZKL_BUF_CAPACITY, EZKL_KEY_FORMAT};
use halo2_proofs::poly::commitment::{CommitmentScheme, Params};
pub(crate) use halo2_proofs::poly::ipa::strategy::AccumulatorStrategy as IPAAccumulatorStrategy;
pub(crate) use halo2_proofs::poly::ipa::strategy::SingleStrategy as IPASingleStrategy;
pub(crate) use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy as KZGAccumulatorStrategy;
pub(crate) use halo2_proofs::poly::kzg::strategy::SingleStrategy as KZGSingleStrategy;
use std::fmt::Display;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use ezkl::pfsys::PfsysError;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::halo2curves::ff::{FromUniformBytes, PrimeField};
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::plonk::{Circuit, VerifyingKey};
use uniffi::deps::log::{debug, info};

/// Deserialise a verification key from a byte
pub fn deserialise_vk<Scheme: CommitmentScheme, C: Circuit<Scheme::Scalar>>(
    path: PathBuf,
    params: <C as Circuit<Scheme::Scalar>>::Params,
) -> Result<VerifyingKey<Scheme::Curve>, PfsysError>
where
    C: Circuit<Scheme::Scalar>,
    Scheme::Curve: SerdeObject + CurveAffine,
    Scheme::Scalar: PrimeField + SerdeObject + FromUniformBytes<64>,
{
    debug!("loading verification key from {:?}", path);
    let f = File::open(path.clone()).map_err(|e| PfsysError::LoadVk(format!("{}", e)))?;
    let mut reader = BufReader::with_capacity(*EZKL_BUF_CAPACITY, f);
    let vk = VerifyingKey::<Scheme::Curve>::read::<_, C>(
        &mut reader,
        serde_format_from_str(&EZKL_KEY_FORMAT),
        params,
    )
    .map_err(|e| PfsysError::LoadVk(format!("{}", e)))?;
    info!("loaded verification key ✅");
    Ok(vk)
}

pub(crate) fn load_params_prover<Scheme: CommitmentScheme>(
    srs_path: Option<PathBuf>,
    logrows: u32,
) -> Result<Scheme::ParamsProver, InnerEZKLError> {
    let srs_path = srs_path.ok_or(InnerEZKLError::UncategorizedError(
        "SRS path must be provided".to_string(),
    ))?;
    let mut params = load_srs_prover::<Scheme>(srs_path)?;
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
    use crate::util::load_params_prover;
    use ezkl::graph::{GraphCircuit, GraphWitness};
    use ezkl::pfsys::{create_keys, save_pk, save_vk};
    use ezkl::Commitments;
    use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
    use halo2_proofs::poly::ipa::commitment::IPACommitmentScheme;
    use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
    use std::path::PathBuf;

    pub fn setup_keys(
        compiled_circuit: PathBuf,
        srs_path: Option<PathBuf>,
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
                let params = load_params_prover::<KZGCommitmentScheme<Bn256>>(srs_path, logrows)?;
                create_keys::<KZGCommitmentScheme<Bn256>, GraphCircuit>(
                    &circuit,
                    &params,
                    disable_selector_compression,
                )?
            }
            Commitments::IPA => {
                let params =
                    load_params_prover::<IPACommitmentScheme<G1Affine>>(srs_path, logrows)?;
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
