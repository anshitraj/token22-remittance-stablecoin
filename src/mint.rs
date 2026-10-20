//! Task 1 and Task 5: building the stablecoin mint.
//!
//! Two issuances share one builder:
//!
//! * **v1**: `TransferFeeConfig` + `MetadataPointer` (pointing at the mint
//!   itself) + `DefaultAccountState(Frozen)` + `MintCloseAuthority`.
//! * **v2**: everything in v1, plus `PermanentDelegate` (seizure authority),
//!   `ConfidentialTransferMint` (manual approval) and
//!   `ConfidentialTransferFeeConfig`.
//!
//! The last extension is not in the assignment text but is not optional: a
//! confidential transfer on a mint that also charges a transfer fee must carry
//! the fee proofs, and Token-2022 rejects it unless the mint holds the
//! withdraw-withheld ElGamal key.

use {
    crate::{Error, Pubkey, Result, token_program_id},
    solana_instruction::Instruction,
    solana_system_interface::instruction as system_instruction,
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
    spl_token_2022_interface::{
        extension::{
            ExtensionType, confidential_transfer::instruction as confidential_transfer_ix,
            confidential_transfer_fee::instruction as confidential_transfer_fee_ix,
            default_account_state::instruction::initialize_default_account_state,
            metadata_pointer::instruction as metadata_pointer_ix,
            transfer_fee::instruction::initialize_transfer_fee_config,
        },
        instruction::{
            initialize_mint_close_authority, initialize_mint2, initialize_permanent_delegate,
        },
        state::{AccountState, Mint},
    },
    spl_token_metadata_interface::{
        instruction as metadata_ix,
        state::{Field, TokenMetadata},
    },
};

/// On-chain metadata. Stored in the mint account itself.
#[derive(Clone, Debug)]
pub struct MetadataParams {
    pub name: String,
    pub symbol: String,
    pub uri: String,
    /// Extra key/value pairs, e.g. the issuer's legal entity or KYC policy URL.
    pub additional: Vec<(String, String)>,
}

/// Parameters shared by both issuances.
#[derive(Clone, Debug)]
pub struct MintParams {
    pub decimals: u8,
    /// Mints new supply.
    pub mint_authority: Pubkey,
    /// Thaws KYC-cleared accounts, freezes sanctioned ones and may change the
    /// mint's default account state.
    pub freeze_authority: Pubkey,
    /// May close the mint once supply is zero (decommissioning).
    pub close_authority: Pubkey,
    /// May schedule new transfer-fee rates.
    pub transfer_fee_config_authority: Pubkey,
    /// May withdraw withheld (public) fees.
    pub withdraw_withheld_authority: Pubkey,
    pub fee_basis_points: u16,
    pub maximum_fee: u64,
    /// Authority over the `MetadataPointer` and the metadata contents.
    pub metadata_update_authority: Pubkey,
    pub metadata: MetadataParams,
}

/// How a confidentially-configured token account gets approved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovePolicy {
    /// `auto_approve_new_accounts = false`: the confidential-transfer authority
    /// must call `ApproveAccount` for each account. This is what Task 5 asks for.
    Manual,
    /// Every configured account is approved immediately. Provided only so tests
    /// can show the contrast; never use for a regulated issuance.
    Auto,
}

/// The additions that turn v1 into v2.
#[derive(Clone, Debug)]
pub struct ReissueParams {
    /// Seizure authority: may transfer or burn from *any* token account of the
    /// mint, without the owner's signature.
    pub permanent_delegate: Pubkey,
    /// May approve confidential accounts and update the auditor key.
    pub confidential_transfer_authority: Pubkey,
    pub approve_policy: ApprovePolicy,
    /// Optional auditor. Every confidential transfer then carries a copy of
    /// the amount encrypted to this key.
    pub auditor_elgamal_pubkey: Option<PodElGamalPubkey>,
    /// ElGamal key that can decrypt fees withheld by *confidential* transfers.
    pub withdraw_withheld_elgamal_pubkey: PodElGamalPubkey,
}

/// Extensions of the first issuance.
pub fn v1_extensions() -> Vec<ExtensionType> {
    vec![
        ExtensionType::TransferFeeConfig,
        ExtensionType::MetadataPointer,
        ExtensionType::DefaultAccountState,
        ExtensionType::MintCloseAuthority,
    ]
}

/// Extensions of the re-issued mint: the v1 set carried forward, plus three.
pub fn v2_extensions() -> Vec<ExtensionType> {
    let mut extensions = v1_extensions();
    extensions.extend([
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialTransferFeeConfig,
    ]);
    extensions
}

/// Bytes to allocate for the mint account, sized by Token-2022's own
/// calculator rather than by hand.
///
/// `TokenMetadata` is variable-length and deliberately absent from the list:
/// `try_calculate_account_len` refuses variable-length extensions. The metadata
/// grows the account later, see [`MintLayout`].
pub fn mint_account_len(extensions: &[ExtensionType]) -> Result<usize> {
    Ok(ExtensionType::try_calculate_account_len::<Mint>(
        extensions,
    )?)
}

/// Size bookkeeping for a mint that stores its own metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MintLayout {
    /// What `CreateAccount` allocates: `try_calculate_account_len` of the fixed
    /// extensions.
    pub allocated_len: usize,
    /// Bytes `InitializeTokenMetadata` appends after the mint is initialized.
    pub metadata_len: usize,
    /// What the lamports must cover: allocation plus the metadata that will be
    /// reallocated in. Funding only `allocated_len` makes the metadata
    /// instruction fail the rent-exemption check.
    pub funded_len: usize,
}

pub fn mint_layout(
    mint: &Pubkey,
    extensions: &[ExtensionType],
    metadata: &MetadataParams,
) -> Result<MintLayout> {
    let allocated_len = mint_account_len(extensions)?;
    // `tlv_size_of` comes from the generic `spl-type-length-value` crate, whose
    // header is an 8-byte discriminator plus a 4-byte length. Token-2022 stores
    // its extensions with a 2-byte type plus a 2-byte length, so the generic
    // figure is 8 bytes too large for an account that Token-2022 will realloc.
    const GENERIC_TLV_HEADER_LEN: usize = 12;
    const TOKEN_2022_TLV_HEADER_LEN: usize = 4;
    let metadata_len = token_metadata(mint, metadata).tlv_size_of()? - GENERIC_TLV_HEADER_LEN
        + TOKEN_2022_TLV_HEADER_LEN;
    Ok(MintLayout {
        allocated_len,
        metadata_len,
        funded_len: allocated_len + metadata_len,
    })
}

fn token_metadata(mint: &Pubkey, metadata: &MetadataParams) -> TokenMetadata {
    // `update_authority` is a fixed 32 bytes whether set or not, so leaving the
    // default does not change the serialized length.
    TokenMetadata {
        mint: *mint,
        name: metadata.name.clone(),
        symbol: metadata.symbol.clone(),
        uri: metadata.uri.clone(),
        additional_metadata: metadata.additional.clone(),
        ..Default::default()
    }
}

/// Task 1: instructions that create the v1 mint.
///
/// Signers: `payer`, the `mint` keypair, `params.mint_authority` (Token-2022
/// requires the mint authority to sign the metadata initialization) and
/// `params.metadata_update_authority` (it signs each `additional` field
/// update). `rent_exempt` maps an account length to its rent-exempt minimum.
pub fn create_mint_v1(
    payer: &Pubkey,
    mint: &Pubkey,
    params: &MintParams,
    rent_exempt: impl Fn(usize) -> u64,
) -> Result<Vec<Instruction>> {
    build(payer, mint, params, None, rent_exempt)
}

/// Task 5: instructions that create the re-issued v2 mint.
///
/// Confidential transfers cannot be added to an existing mint, so this is a
/// *new* mint address that carries the v1 extension set forward.
pub fn create_mint_v2(
    payer: &Pubkey,
    mint: &Pubkey,
    params: &MintParams,
    reissue: &ReissueParams,
    rent_exempt: impl Fn(usize) -> u64,
) -> Result<Vec<Instruction>> {
    build(payer, mint, params, Some(reissue), rent_exempt)
}

#[allow(clippy::vec_init_then_push)]
fn build(
    payer: &Pubkey,
    mint: &Pubkey,
    params: &MintParams,
    reissue: Option<&ReissueParams>,
    rent_exempt: impl Fn(usize) -> u64,
) -> Result<Vec<Instruction>> {
    let token_program = token_program_id();
    let extensions = if reissue.is_some() {
        v2_extensions()
    } else {
        v1_extensions()
    };
    let layout = mint_layout(mint, &extensions, &params.metadata)?;

    #[allow(clippy::vec_init_then_push)]
    let mut ixs = Vec::new();

    // 1. Allocate exactly the fixed-extension size, funded for the metadata too.
    ixs.push(system_instruction::create_account(
        payer,
        mint,
        rent_exempt(layout.funded_len),
        layout.allocated_len as u64,
        &token_program,
    ));

    // 2. Every extension initializer. Token-2022 rejects them once the base
    //    mint is initialized, so they all sit before `InitializeMint2`.
    ixs.push(initialize_transfer_fee_config(
        &token_program,
        mint,
        Some(&params.transfer_fee_config_authority),
        Some(&params.withdraw_withheld_authority),
        params.fee_basis_points,
        params.maximum_fee,
    )?);
    ixs.push(metadata_pointer_ix::initialize(
        &token_program,
        mint,
        Some(params.metadata_update_authority),
        Some(*mint), // the metadata lives in the mint account itself
    )?);
    ixs.push(initialize_default_account_state(
        &token_program,
        mint,
        &AccountState::Frozen,
    )?);
    ixs.push(initialize_mint_close_authority(
        &token_program,
        mint,
        Some(&params.close_authority),
    )?);

    if let Some(reissue) = reissue {
        ixs.push(initialize_permanent_delegate(
            &token_program,
            mint,
            &reissue.permanent_delegate,
        )?);
        ixs.push(confidential_transfer_ix::initialize_mint(
            &token_program,
            mint,
            Some(reissue.confidential_transfer_authority),
            reissue.approve_policy == ApprovePolicy::Auto,
            reissue.auditor_elgamal_pubkey,
        )?);
        ixs.push(
            confidential_transfer_fee_ix::initialize_confidential_transfer_fee_config(
                &token_program,
                mint,
                Some(reissue.confidential_transfer_authority),
                &reissue.withdraw_withheld_elgamal_pubkey,
            )?,
        );
    }

    // 3. Base mint. A freeze authority is mandatory here: with
    //    `DefaultAccountState(Frozen)` and no freeze authority every new
    //    account would be frozen forever.
    ixs.push(initialize_mint2(
        &token_program,
        mint,
        &params.mint_authority,
        Some(&params.freeze_authority),
        params.decimals,
    )?);

    // 4. Metadata (variable length, written after the mint exists).
    ixs.push(metadata_ix::initialize(
        &token_program,
        mint,
        &params.metadata_update_authority,
        mint,
        &params.mint_authority,
        params.metadata.name.clone(),
        params.metadata.symbol.clone(),
        params.metadata.uri.clone(),
    ));
    for (key, value) in &params.metadata.additional {
        ixs.push(metadata_ix::update_field(
            &token_program,
            mint,
            &params.metadata_update_authority,
            Field::Key(key.clone()),
            value.clone(),
        ));
    }

    Ok(ixs)
}

/// Where `InitializeMint2` sits in an instruction list, and whether every
/// extension initializer comes before it. Used by tests to pin down the
/// ordering rule from the assignment.
pub fn initializers_precede_initialize_mint(ixs: &[Instruction]) -> Result<bool> {
    use spl_token_2022_interface::instruction::TokenInstruction;

    let token_program = token_program_id();
    let mut mint_initialized_at = None;
    let mut last_extension_init_at = None;

    for (index, ix) in ixs.iter().enumerate() {
        if ix.program_id != token_program {
            continue;
        }
        match TokenInstruction::unpack(&ix.data) {
            Ok(TokenInstruction::InitializeMint2 { .. }) => mint_initialized_at = Some(index),
            Ok(TokenInstruction::TransferFeeExtension)
            | Ok(TokenInstruction::MetadataPointerExtension)
            | Ok(TokenInstruction::DefaultAccountStateExtension)
            | Ok(TokenInstruction::InitializeMintCloseAuthority { .. })
            | Ok(TokenInstruction::InitializePermanentDelegate { .. })
            | Ok(TokenInstruction::ConfidentialTransferExtension)
            | Ok(TokenInstruction::ConfidentialTransferFeeExtension) => {
                last_extension_init_at = Some(index)
            }
            _ => {}
        }
    }

    match (mint_initialized_at, last_extension_init_at) {
        (Some(mint_at), Some(ext_at)) => Ok(ext_at < mint_at),
        (None, _) => Err(Error::Program(
            solana_program_error::ProgramError::InvalidInstructionData,
        )),
        (Some(_), None) => Ok(true),
    }
}
