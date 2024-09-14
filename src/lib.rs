mod gen_witness;
mod prove;
mod serialization;
mod verify;

pub use gen_witness::gen_witness_wrapper;
pub use prove::{prove_advanced_wrapper, prove_wrapper};
use std::fmt::Display;
pub use verify::verify_wrapper;

pub(crate) use ezkl::EZKLError as InnerEZKLError;
pub(crate) use halo2_proofs::poly::ipa::strategy::AccumulatorStrategy as IPAAccumulatorStrategy;
pub(crate) use halo2_proofs::poly::ipa::strategy::SingleStrategy as IPASingleStrategy;
pub(crate) use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy as KZGAccumulatorStrategy;
pub(crate) use halo2_proofs::poly::kzg::strategy::SingleStrategy as KZGSingleStrategy;

uniffi::setup_scaffolding!();

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

pub mod testing {
    pub use crate::serialization::deserialize_params_prover;
}

// 1. Setup - on computer   - compile `.onnx` circuit to `.ezkl` circuit, generate settings file
//                          - set up the model using the EZKL cli
//                          - download / generate the srs, and for it generate the vk and pk
//                          - upload the srs, vk, and pk to the phone
//
// 2. Prove - on phone      - download the srs
//                          - download / load the pk, vk, and the circuit
//                          - use EZKL FFI to generate the witness
//                          - use EZKL FFI to generate the proof
//
//
// 3. Verify - on phone     - download the srs, settings of the model
//                          - get the proof
//                          - use EZKL FFI to verify the proof
//
// 3+ EVM verify - on phone - TBD
//
// 4. Aggr - on server      - download the proofs
//                          - this is done on the server because it requires a lot of memory
