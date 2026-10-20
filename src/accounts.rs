//! Token account creation.
//!
//! Creating an associated token account is **permissionless**: the payer is
//! whoever funds it, the owner does not sign, and the address is a pure function
//! of `(owner, mint, token program)`. That is convenient (anyone can pay to give
//! you an account) and it is exactly why account creation can never be the step
//! that opts a wallet into confidential transfers. See
//! [`crate::confidential::configure_account`], which only the owner can sign.

use {
    crate::{Pubkey, token_program_id},
    solana_instruction::Instruction,
    spl_associated_token_account_interface::{
        address::get_associated_token_address_with_program_id,
        instruction::create_associated_token_account_idempotent,
    },
};

/// The owner's associated token account for `mint`.
pub fn ata_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    get_associated_token_address_with_program_id(owner, mint, &token_program_id())
}

/// Create (idempotently) `owner`'s ATA, paid for by `payer`.
///
/// The ATA program sizes the account for every extension the mint requires on
/// accounts (`ImmutableOwner`, `TransferFeeAmount`) and, because the mint has
/// `DefaultAccountState(Frozen)`, initializes it frozen.
pub fn create_ata(payer: &Pubkey, owner: &Pubkey, mint: &Pubkey) -> Instruction {
    create_associated_token_account_idempotent(payer, owner, mint, &token_program_id())
}
