//! Remittance stablecoin on SPL Token-2022.
//!
//! The crate is an off-chain client library: it builds Token-2022 instructions
//! (and the zero-knowledge proofs confidential transfers need) and reads
//! on-chain state. Nothing here signs or sends; callers own the transport.
//!
//! | Assignment task | Module |
//! |---|---|
//! | 1. Mint with stacked extensions            | [`mint`] |
//! | 2. `transfer_checked_with_fee`             | [`transfer`] |
//! | 3. Reads through `StateWithExtensions`     | [`state`] |
//! | 4. KYC thaw path                           | [`kyc`] |
//! | 5. Re-issue with seizure + confidentiality | [`mint`], [`seizure`] |
//! | 6. Confidential lifecycle                  | [`confidential`], [`record`] |

pub mod accounts;
pub mod chain;
pub mod confidential;
pub mod error;
pub mod kyc;
pub mod mint;
pub mod record;
pub mod seizure;
pub mod state;
pub mod transfer;

pub use {
    chain::ChainReader,
    error::{Error, Result},
    solana_address::Address as Pubkey,
};

/// The Token-2022 program id.
pub fn token_program_id() -> Pubkey {
    spl_token_2022_interface::id()
}
