//! Task 4: the unfreeze (KYC) path.
//!
//! With `DefaultAccountState(Frozen)` every new token account starts frozen.
//! Two *different* levers exist and they are deliberately kept apart:
//!
//! * [`thaw_after_kyc`]: `ThawAccount`, signed by the freeze authority, affects
//!   exactly **one** token account.
//! * [`set_default_account_state`]: `UpdateDefaultAccountState`, also signed by
//!   the freeze authority, affects only accounts created **afterwards**. It
//!   never touches an account that already exists, frozen or not.
//!
//! Neither can be performed by the account owner, which is what makes the
//! freeze a real compliance control.

use {
    crate::{ChainReader, Error, Pubkey, Result, chain::require_account_data, token_program_id},
    solana_instruction::Instruction,
    spl_token_2022_interface::{
        extension::{
            StateWithExtensions, default_account_state::instruction::update_default_account_state,
        },
        instruction::{freeze_account, thaw_account},
        state::{Account, AccountState, Mint},
    },
};

/// Thaw one account after the issuer has cleared its owner.
///
/// Fails fast, off-chain, if the account is not frozen or if `freeze_authority`
/// is not the mint's freeze authority; the chain would reject both, but the
/// caller gets a precise reason instead of a bare custom error code.
pub fn thaw_after_kyc<C: ChainReader + ?Sized>(
    chain: &C,
    token_account: &Pubkey,
    freeze_authority: &Pubkey,
) -> Result<Instruction> {
    let account_data = require_account_data(chain, token_account)?;
    let account = StateWithExtensions::<Account>::unpack(&account_data)?;
    if account.base.state != AccountState::Frozen {
        return Err(Error::NotFrozen(*token_account));
    }
    let mint = account.base.mint;

    check_freeze_authority(chain, &mint, freeze_authority)?;

    Ok(thaw_account(
        &token_program_id(),
        token_account,
        &mint,
        freeze_authority,
        &[],
    )?)
}

/// Freeze one account, e.g. when its owner appears on a sanctions list.
pub fn freeze<C: ChainReader + ?Sized>(
    chain: &C,
    token_account: &Pubkey,
    freeze_authority: &Pubkey,
) -> Result<Instruction> {
    let account_data = require_account_data(chain, token_account)?;
    let mint = StateWithExtensions::<Account>::unpack(&account_data)?
        .base
        .mint;
    check_freeze_authority(chain, &mint, freeze_authority)?;

    Ok(freeze_account(
        &token_program_id(),
        token_account,
        &mint,
        freeze_authority,
        &[],
    )?)
}

/// Change the state future accounts are created in. Mint-level only.
pub fn set_default_account_state(
    mint: &Pubkey,
    freeze_authority: &Pubkey,
    state: AccountState,
) -> Result<Instruction> {
    Ok(update_default_account_state(
        &token_program_id(),
        mint,
        freeze_authority,
        &[],
        &state,
    )?)
}

fn check_freeze_authority<C: ChainReader + ?Sized>(
    chain: &C,
    mint: &Pubkey,
    signer: &Pubkey,
) -> Result<()> {
    let mint_data = require_account_data(chain, mint)?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data)?;
    let Some(authority) = Option::<Pubkey>::from(mint_state.base.freeze_authority) else {
        return Err(Error::NoFreezeAuthority);
    };
    if authority != *signer {
        return Err(Error::WrongAuthority {
            signer: *signer,
            role: "freeze authority",
        });
    }
    Ok(())
}
