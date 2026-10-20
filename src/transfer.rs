//! Task 2: fee-aware transfers.
//!
//! On a mint with `TransferFeeConfig` a plain `TransferChecked` still works: the
//! program computes the fee itself and withholds it. The sender has no say, and
//! if the fee schedule changes between quoting and landing, the sender silently
//! pays the new rate.
//!
//! `TransferCheckedWithFee` closes that gap. The sender states the fee it
//! expects and the program compares it with its own calculation, failing with
//! `FeeMismatch` on disagreement. The fee becomes an explicit, asserted part of
//! the instruction instead of an implicit side effect.
//!
//! The expected fee is computed from the mint's *current* on-chain schedule via
//! [`TransferFeeConfig::calculate_epoch_fee`]. The schedule holds two entries
//! (`older`, `newer`) and a fee change only takes effect from the `newer`
//! entry's epoch, so a rate cached from an earlier read is silently wrong
//! around a fee change. Nothing in this crate caches a rate.

use {
    crate::{ChainReader, Error, Pubkey, Result, chain::require_account_data, token_program_id},
    solana_instruction::Instruction,
    spl_token_2022_interface::{
        extension::{
            BaseStateWithExtensions, ExtensionType, StateWithExtensions,
            transfer_fee::{TransferFeeConfig, instruction::transfer_checked_with_fee},
        },
        state::{Account, Mint},
    },
};

/// The result of pricing one transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeQuote {
    pub amount: u64,
    pub fee: u64,
    pub decimals: u8,
    /// Epoch the fee was priced in.
    pub epoch: u64,
    /// The schedule entry that applied in `epoch`.
    pub basis_points: u16,
    pub maximum_fee: u64,
}

impl FeeQuote {
    /// What the destination receives.
    pub fn net_amount(&self) -> u64 {
        self.amount - self.fee
    }
}

/// Price a transfer of `amount` against the mint data, in `epoch`.
///
/// Pure function of its inputs: the caller supplies the epoch, so it can be
/// tested at any point in a fee schedule.
pub fn quote_fee(mint_data: &[u8], epoch: u64, amount: u64) -> Result<FeeQuote> {
    let mint = StateWithExtensions::<Mint>::unpack(mint_data)?;
    let config = mint
        .get_extension::<TransferFeeConfig>()
        .map_err(|_| Error::MissingExtension(ExtensionType::TransferFeeConfig))?;

    let fee = config
        .calculate_epoch_fee(epoch, amount)
        .ok_or(Error::FeeOverflow)?;
    let applied = config.get_epoch_fee(epoch);

    Ok(FeeQuote {
        amount,
        fee,
        decimals: mint.base.decimals,
        epoch,
        basis_points: u16::from(applied.transfer_fee_basis_points),
        maximum_fee: u64::from(applied.maximum_fee),
    })
}

/// Build the transfer instruction from an already-computed quote.
pub fn transfer_with_fee_ix(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    quote: &FeeQuote,
) -> Result<Instruction> {
    Ok(transfer_checked_with_fee(
        &token_program_id(),
        source,
        mint,
        destination,
        authority,
        &[],
        quote.amount,
        quote.decimals,
        quote.fee,
    )?)
}

/// Task 2 entry point: transfer `amount` from `source` to `destination`.
///
/// Reads the source account to find the mint, reads the mint's fee schedule,
/// prices the transfer in the cluster's current epoch and emits
/// `TransferCheckedWithFee`. `authority` is whoever signs for the source: the
/// owner, a delegate, or the permanent delegate.
pub fn transfer_with_fee<C: ChainReader + ?Sized>(
    chain: &C,
    source: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> Result<Instruction> {
    let source_data = require_account_data(chain, source)?;
    let mint = StateWithExtensions::<Account>::unpack(&source_data)?
        .base
        .mint;

    let mint_data = require_account_data(chain, &mint)?;
    let quote = quote_fee(&mint_data, chain.current_epoch(), amount)?;

    transfer_with_fee_ix(source, &mint, destination, authority, &quote)
}
