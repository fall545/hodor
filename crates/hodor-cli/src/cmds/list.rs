//! `hodor list`: object inventory (aliases and policies, never values).

use anyhow::Result;

use super::unlock_vault;
use crate::config::Config;
use crate::i18n::Msgs;

pub fn run(msgs: &Msgs, cfg: &Config) -> Result<()> {
    let unlocked = unlock_vault(msgs, cfg)?;
    println!("{}", msgs.get("objects-title", &[]));
    for object in &unlocked.content.objects {
        let confirm = match object.policy.confirm {
            hodor_core::object::ConfirmMode::Always => "always",
            hodor_core::object::ConfirmMode::Task => "task",
            hodor_core::object::ConfirmMode::Whitelisted => "whitelisted",
        };
        println!(
            "{:<16} {:<8} confirm={:<12} uses={}",
            object.alias,
            object.kind.as_str(),
            confirm,
            object.policy.uses.summary()
        );
    }
    let _ = unlocked.lock();
    Ok(())
}
