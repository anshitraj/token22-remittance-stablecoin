//! Task 3: read account and mint state **only** through `StateWithExtensions`.
//!
//! Token-2022 accounts are `base state ++ account-type byte ++ TLV extensions`.
//! A raw `Mint::unpack` / `Account::unpack` on such data is wrong in both
//! directions: it can reject a perfectly valid extended account (length is not
//! the base length) and, on the unchecked variant, it ignores the account-type
//! byte and happily "reads" the wrong kind of account.
//! `StateWithExtensions::unpack` validates the length, the account-type
//! discriminator and the TLV layout before handing back the base state and
//! typed extensions.
//!
//! The `no_raw_unpack` integration test greps this crate for the banned calls.

use {
    crate::{Error, Pubkey, Result},
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
    spl_token_2022_interface::{
        extension::{
            BaseStateWithExtensions, ExtensionType, StateWithExtensions,
            confidential_transfer::{ConfidentialTransferAccount, ConfidentialTransferMint},
            cpi_guard::CpiGuard,
            default_account_state::DefaultAccountState,
            metadata_pointer::MetadataPointer,
            mint_close_authority::MintCloseAuthority,
            permanent_delegate::PermanentDelegate,
            transfer_fee::{TransferFee, TransferFeeAmount, TransferFeeConfig},
        },
        state::{Account, AccountState, Mint},
    },
    spl_token_metadata_interface::state::TokenMetadata,
};

/// One entry of the fee schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRate {
    /// First epoch in which this rate applies.
    pub epoch: u64,
    pub basis_points: u16,
    pub maximum_fee: u64,
}

impl From<&TransferFee> for FeeRate {
    fn from(fee: &TransferFee) -> Self {
        Self {
            epoch: u64::from(fee.epoch),
            basis_points: u16::from(fee.transfer_fee_basis_points),
            maximum_fee: u64::from(fee.maximum_fee),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransferFeeView {
    pub config_authority: Option<Pubkey>,
    pub withdraw_withheld_authority: Option<Pubkey>,
    /// Fees already harvested into the mint and not yet withdrawn.
    pub withheld_amount: u64,
    pub older: FeeRate,
    pub newer: FeeRate,
}

#[derive(Clone, Debug)]
pub struct ConfidentialMintView {
    pub authority: Option<Pubkey>,
    pub auto_approve_new_accounts: bool,
    pub auditor_elgamal_pubkey: Option<PodElGamalPubkey>,
}

#[derive(Clone, Debug)]
pub struct MintView {
    pub supply: u64,
    pub decimals: u8,
    pub mint_authority: Option<Pubkey>,
    pub freeze_authority: Option<Pubkey>,
    /// Every fixed-size extension present, in on-chain TLV order.
    pub extensions: Vec<ExtensionType>,
    pub transfer_fee: Option<TransferFeeView>,
    pub metadata_pointer_authority: Option<Pubkey>,
    pub metadata_pointer_address: Option<Pubkey>,
    pub default_account_state: Option<AccountState>,
    pub close_authority: Option<Pubkey>,
    pub permanent_delegate: Option<Pubkey>,
    pub confidential_transfer: Option<ConfidentialMintView>,
    pub token_metadata: Option<TokenMetadata>,
}

pub fn read_mint(data: &[u8]) -> Result<MintView> {
    let mint = StateWithExtensions::<Mint>::unpack(data)?;

    let transfer_fee = mint
        .get_extension::<TransferFeeConfig>()
        .ok()
        .map(|config| TransferFeeView {
            config_authority: config.transfer_fee_config_authority.into(),
            withdraw_withheld_authority: config.withdraw_withheld_authority.into(),
            withheld_amount: u64::from(config.withheld_amount),
            older: FeeRate::from(&config.older_transfer_fee),
            newer: FeeRate::from(&config.newer_transfer_fee),
        });

    let metadata_pointer = mint.get_extension::<MetadataPointer>().ok();

    Ok(MintView {
        supply: mint.base.supply,
        decimals: mint.base.decimals,
        mint_authority: mint.base.mint_authority.into(),
        freeze_authority: mint.base.freeze_authority.into(),
        extensions: mint.get_extension_types()?,
        transfer_fee,
        metadata_pointer_authority: metadata_pointer.and_then(|p| p.authority.into()),
        metadata_pointer_address: metadata_pointer.and_then(|p| p.metadata_address.into()),
        default_account_state: mint
            .get_extension::<DefaultAccountState>()
            .ok()
            .and_then(|ext| AccountState::try_from(ext.state).ok()),
        close_authority: mint
            .get_extension::<MintCloseAuthority>()
            .ok()
            .and_then(|ext| ext.close_authority.into()),
        permanent_delegate: mint
            .get_extension::<PermanentDelegate>()
            .ok()
            .and_then(|ext| ext.delegate.into()),
        confidential_transfer: mint
            .get_extension::<ConfidentialTransferMint>()
            .ok()
            .map(|ext| ConfidentialMintView {
                authority: ext.authority.into(),
                auto_approve_new_accounts: ext.auto_approve_new_accounts.into(),
                auditor_elgamal_pubkey: ext.auditor_elgamal_pubkey.into(),
            }),
        token_metadata: mint.get_variable_len_extension::<TokenMetadata>().ok(),
    })
}

#[derive(Clone, Debug)]
pub struct AccountView {
    pub mint: Pubkey,
    pub owner: Pubkey,
    /// Public (non-confidential) balance.
    pub amount: u64,
    pub delegate: Option<Pubkey>,
    pub delegated_amount: u64,
    pub state: AccountState,
    pub close_authority: Option<Pubkey>,
    pub extensions: Vec<ExtensionType>,
    /// Transfer fees this account has received and not yet harvested.
    pub withheld_fee: Option<u64>,
    pub cpi_guard_enabled: Option<bool>,
    /// Confidential-transfer state: ciphertexts, counters, approval flag.
    pub confidential: Option<ConfidentialTransferAccount>,
}

pub fn read_account(data: &[u8]) -> Result<AccountView> {
    let account = StateWithExtensions::<Account>::unpack(data)?;

    Ok(AccountView {
        mint: account.base.mint,
        owner: account.base.owner,
        amount: account.base.amount,
        delegate: account.base.delegate.into(),
        delegated_amount: account.base.delegated_amount,
        state: account.base.state,
        close_authority: account.base.close_authority.into(),
        extensions: account.get_extension_types()?,
        withheld_fee: account
            .get_extension::<TransferFeeAmount>()
            .ok()
            .map(|ext| u64::from(ext.withheld_amount)),
        cpi_guard_enabled: account
            .get_extension::<CpiGuard>()
            .ok()
            .map(|ext| bool::from(ext.lock_cpi)),
        confidential: account
            .get_extension::<ConfidentialTransferAccount>()
            .ok()
            .copied(),
    })
}

/// Convenience wrappers that fetch through a [`crate::ChainReader`].
pub fn fetch_mint<C: crate::ChainReader + ?Sized>(chain: &C, mint: &Pubkey) -> Result<MintView> {
    let data = chain
        .account_data(mint)
        .ok_or(Error::AccountNotFound(*mint))?;
    read_mint(&data)
}

pub fn fetch_account<C: crate::ChainReader + ?Sized>(
    chain: &C,
    account: &Pubkey,
) -> Result<AccountView> {
    let data = chain
        .account_data(account)
        .ok_or(Error::AccountNotFound(*account))?;
    read_account(&data)
}
