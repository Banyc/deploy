//! The per-surface policy leaves: each is a distinct, independently-validated
//! config surface — [`pins`] (durable release pins), [`slots`] (deployment
//! slots), [`rollout`] (target rollout policy), [`retention`] (slot-owned
//! deployment retention), [`activation`] (activation policy), [`verification`]
//! (verification policy), [`servers`] (server connection + identity),
//! [`capacity`] (per-server capacity), [`release_name`] (release names).
//! Each module is re-exported at `crate::config::<name>` by `config/mod.rs`.

pub(crate) mod activation;
pub(crate) mod capacity;
pub(crate) mod pins;
pub(crate) mod release_name;
pub(crate) mod retention;
pub(crate) mod rollout;
pub(crate) mod servers;
pub(crate) mod slots;
pub(crate) mod verification;
