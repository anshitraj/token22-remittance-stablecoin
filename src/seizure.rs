//! Task 5 (seizure half): what the `PermanentDelegate` can and cannot do.
//!
//! The permanent delegate may `Transfer`/`Burn` from **any** token account of
//! the mint without the owner's signature. That power covers only the account's
//! *public* balance (`Account::amount`). Confidential balances live in
//! ciphertext fields that the permanent delegate has no way to move, and no
//! confidential-transfer instruction recognises it as an authority. See
//! `docs/WRITTEN_FINDING.md`.
//!
//! Also note two interactions that bite in practice:
//!
//! * A **frozen** account cannot be seized: Token-2022 checks the frozen flag
//!   before the authority. Seizure of a frozen account therefore needs a thaw
//!   first, i.e. the freeze authority has to cooperate.
//! * Seizure by transfer is still a transfer: the fee is charged. The issuer
//!   holds the withdraw-withheld authority, so the fee flows back to it, but the
//!   instruction must be `TransferCheckedWithFee` with the correct fee.

use {
    crate::{
        ChainReader, Error, Pubkey, Result,
        chain::require_account_data,
        token_program_id,
        transfer::{quote_fee, transfer_with_fee_ix},
    },
    solana_instruction::Instruction,
    spl_token_2022_interface::{
        extension::{
            BaseStateWithExtensions, StateWithExtensions, permanent_delegate::PermanentDelegate,
        },
        instruction::burn_checked,
        state::{Account, Mint},
    },
};

/// Move the account's entire public balance to `destination` (the issuer's
/// treasury), signed by the permanent delegate.
pub fn seize_public_balance<C: ChainReader + ?Sized>(
    chain: &C,
    source: &Pubkey,
    destination: &Pubkey,
    permanent_delegate: &Pubkey,
) -> Result<Instruction> {
    let (mint, amount) = source_details(chain, source, permanent_delegate)?;
    let mint_data = require_account_data(chain, &mint)?;
    let quote = quote_fee(&mint_data, chain.current_epoch(), amount)?;
    transfer_with_fee_ix(source, &mint, destination, permanent_delegate, &quote)
}

/// Destroy the account's entire public balance, signed by the permanent
/// delegate. No fee applies to a burn.
pub fn burn_public_balance<C: ChainReader + ?Sized>(
    chain: &C,
    source: &Pubkey,
    permanent_delegate: &Pubkey,
) -> Result<Instruction> {
    let (mint, amount) = source_details(chain, source, permanent_delegate)?;
    let mint_data = require_account_data(chain, &mint)?;
    let decimals = StateWithExtensions::<Mint>::unpack(&mint_data)?
        .base
        .decimals;
    Ok(burn_checked(
        &token_program_id(),
        source,
        &mint,
        permanent_delegate,
        &[],
        amount,
        decimals,
    )?)
}

fn source_details<C: ChainReader + ?Sized>(
    chain: &C,
    source: &Pubkey,
    permanent_delegate: &Pubkey,
) -> Result<(Pubkey, u64)> {
    let source_data = require_account_data(chain, source)?;
    let account = StateWithExtensions::<Account>::unpack(&source_data)?;
    let mint = account.base.mint;

    let mint_data = require_account_data(chain, &mint)?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data)?;
    let configured = mint_state
        .get_extension::<PermanentDelegate>()
        .ok()
        .and_then(|ext| Option::<Pubkey>::from(ext.delegate));
    if configured != Some(*permanent_delegate) {
        return Err(Error::WrongAuthority {
            signer: *permanent_delegate,
            role: "permanent delegate",
        });
    }

    if account.base.amount == 0 {
        return Err(Error::NothingToMove(*source));
    }
    Ok((mint, account.base.amount))
}
