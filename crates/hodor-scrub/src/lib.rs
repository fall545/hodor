//! hodor-scrub: the secret substitution engine (R14).
//!
//! One engine serves two callers: command-output scrubbing (daemon) and
//! file-read alias substitution (hodor-vfs, M4). Never fork this logic.
//!
//! Pure library: no I/O, no processes.

pub mod patterns;
pub mod scanner;
pub mod verdict;

pub use scanner::{ScrubResult, Scrubber, StreamScrubber};
