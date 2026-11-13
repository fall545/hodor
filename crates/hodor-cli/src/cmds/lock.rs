//! `hodor lock`: at CLI level every process exit is a lock (zeroized DEK);
//! this command explains that and will grow daemon teardown in M2.

use anyhow::Result;

use crate::i18n::Msgs;

pub fn run(msgs: &Msgs) -> Result<()> {
    println!("{}", msgs.get("lock-note", &[]));
    Ok(())
}
