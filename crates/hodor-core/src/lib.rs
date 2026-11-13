//! hodor-core: encrypted vault, object model, audit hash chain, and template
//! resolution. This crate is a pure library — no network, no process spawning,
//! no filesystem writes outside explicit vault/audit paths given by the caller.

pub mod audit;
pub mod biometric;
pub mod crypto;
pub mod error;
pub mod object;
pub mod paths;
pub mod templates;
pub mod vault;

pub use error::{CoreError, Result};
