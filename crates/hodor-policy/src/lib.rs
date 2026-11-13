//! hodor-policy: command normalization and the three-layer evaluation engine
//! (R12): hard deny → user deny → whitelist → ask.
//!
//! Pure library: reads the filesystem only for path canonicalization and
//! never writes anything.

pub mod blacklist;
pub mod engine;
pub mod normalize;

pub use blacklist::DenyCategory;
pub use engine::{evaluate, Decision, PolicyData};
pub use normalize::{CommandFeature, NormalizedCommand};
