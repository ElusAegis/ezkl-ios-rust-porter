mod gen_witness;
mod prove;
mod util;
mod verify;

pub use gen_witness::gen_witness_wrapper;
pub use prove::{prove_advanced_wrapper, prove_wrapper};
pub use verify::verify_wrapper;

pub use util::testing::setup_keys;

uniffi::setup_scaffolding!();

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
