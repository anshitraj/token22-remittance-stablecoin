//! Minimal read-only view of the chain.
//!
//! The library never talks to an RPC node or a test VM directly. Everything
//! that needs on-chain state (the current fee schedule, an account's state, the
//! epoch) asks a [`ChainReader`], so the same code runs against LiteSVM in the
//! tests and against a real RPC client in an application.

use crate::{Error, Pubkey, Result};

pub trait ChainReader {
    /// Raw account data, or `None` if the account does not exist.
    fn account_data(&self, address: &Pubkey) -> Option<Vec<u8>>;

    /// Epoch of the cluster clock right now. Fees are epoch-scheduled, so a
    /// transfer must always be priced against the *current* epoch.
    fn current_epoch(&self) -> u64;
}

pub(crate) fn require_account_data<C: ChainReader + ?Sized>(
    chain: &C,
    address: &Pubkey,
) -> Result<Vec<u8>> {
    chain
        .account_data(address)
        .ok_or(Error::AccountNotFound(*address))
}
