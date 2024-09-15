use crate::InnerEZKLError;
use std::fmt::Display;

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

impl From<ezkl::graph::errors::GraphError> for EZKLError {
    fn from(e: ezkl::graph::errors::GraphError) -> Self {
        EZKLError::InternalError(e.to_string())
    }
}
