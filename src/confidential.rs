//! Task 6: the confidential-transfer lifecycle.
//!
//! ```text
//!  anyone ──► create ATA ──────────────┐   permissionless, account starts FROZEN
//!  owner  ──► Reallocate + ConfigureAccount   (owner signature + PubkeyValidity proof)
//!  issuer ──► ApproveAccount           (approve_policy = manual)
//!  issuer ──► ThawAccount              (KYC; default state is Frozen)
//!  owner  ──► DepositConfidentialTokens      public balance ─► pending
//!  owner  ──► ApplyPendingBalance            pending ─► available
//!  owner  ──► confidential Transfer          proofs + TransferWithFee
//!  owner  ──► ApplyPendingBalance            (receiver) pending ─► available
//!  owner  ──► Withdraw                       available ─► public balance
//! ```
//!
//! # Why `TransferWithFee`
//!
//! The mint carries `TransferFeeConfig`. Token-2022 then refuses a fee-less
//! confidential transfer: the sender must prove the fee was computed correctly
//! and encrypt it to the destination and to the mint's withdraw-withheld
//! ElGamal key. That is five zero-knowledge proofs instead of three.
//!
//! # Why so many transactions
//!
//! Proof data is too large to ride along in the transfer transaction (1232
//! byte packet limit). Each proof is verified up front by the ZK ElGamal Proof
//! program, which writes a small *context state account* recording the verified
//! statement; the token instruction then points at those accounts. The largest
//! proof (the 256-bit range proof) does not even fit a transaction on its own,
//! so it is staged through the Record program first. See [`crate::record`].
//!
//! This module only *plans* the work: it returns [`Step`]s of instructions plus
//! the extra keypairs each step needs. The caller signs and submits them in
//! order.

use {
    crate::{
        ChainReader, Error, Pubkey, Result, chain::require_account_data, record, token_program_id,
    },
    bytemuck::Pod,
    solana_compute_budget_interface::ComputeBudgetInstruction,
    solana_instruction::Instruction,
    solana_keypair::Keypair,
    solana_signer::Signer,
    solana_system_interface::instruction as system_instruction,
    solana_zk_sdk::{
        encryption::{
            auth_encryption::{AeCiphertext, AeKey},
            derivation::{confidential_derivation_message, derive_confidential_keys_from_ikm},
            elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
        },
        zk_elgamal_proof_program::build_pubkey_validity_proof_data,
    },
    solana_zk_sdk_pod::encryption::{
        auth_encryption::PodAeCiphertext,
        elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
    },
    spl_token_2022_interface::{
        extension::{
            BaseStateWithExtensions, ExtensionType, StateWithExtensions,
            confidential_transfer::{
                ConfidentialTransferAccount, ConfidentialTransferMint,
                PENDING_BALANCE_LO_BIT_LENGTH, instruction as ct,
            },
            confidential_transfer_fee::ConfidentialTransferFeeConfig,
            transfer_fee::TransferFeeConfig,
        },
        instruction::reallocate,
        solana_zk_elgamal_proof_interface::{
            self,
            instruction::{ContextStateInfo, ProofInstruction, close_context_state},
            proof_data::ZkProofData,
            state::ProofContextState,
        },
        state::{Account, Mint},
    },
    spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation,
    spl_token_confidential_transfer_proof_generation::{
        transfer_with_fee::transfer_with_fee_split_proof_data, withdraw::withdraw_proof_data,
    },
    std::{mem::size_of, num::NonZeroI8},
};

/// Pending credits an account accepts before its owner must `ApplyPendingBalance`.
pub const MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER: u64 = 65_536;

/// Proofs whose instruction data is at most this many bytes are verified
/// straight from instruction data; larger ones are staged in a Record account.
/// Chosen so the verify transaction stays under the 1232-byte packet limit.
const INLINE_PROOF_LIMIT: usize = 800;

const PROOF_VERIFY_COMPUTE_UNITS: u32 = 500_000;
const CONFIDENTIAL_INSTRUCTION_COMPUTE_UNITS: u32 = 1_000_000;

type RentFn<'a> = &'a dyn Fn(usize) -> u64;

fn conf(error: impl std::fmt::Display) -> Error {
    Error::Confidential(error.to_string())
}

fn proof(error: impl std::fmt::Display) -> Error {
    Error::Proof(error.to_string())
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// The two secrets a confidential account owner needs.
///
/// * the ElGamal keypair decrypts the pending balance and proves statements
///   about the available balance;
/// * the AES key decrypts the owner's *own* cached copy of the available
///   balance, which spares a discrete-log search on every read.
pub struct ConfidentialKeys {
    pub elgamal: ElGamalKeypair,
    pub aes: AeKey,
}

impl ConfidentialKeys {
    /// Standard wallet-level derivation: sign the canonical derivation message
    /// once and run HKDF over the signature. These are the same keys the
    /// Token-2022 CLI and JavaScript client derive for the same wallet, so a
    /// user can switch client and still decrypt their balance.
    ///
    /// Anyone who can obtain that one signature can derive the keys, so the
    /// signature itself must never leave the wallet.
    pub fn derive(owner: &dyn Signer) -> Result<Self> {
        let message = confidential_derivation_message(b"");
        let signature = owner.try_sign_message(&message).map_err(conf)?;
        let (elgamal, aes) = derive_confidential_keys_from_ikm(signature.as_ref()).map_err(conf)?;
        Ok(Self { elgamal, aes })
    }

    pub fn elgamal_pubkey(&self) -> PodElGamalPubkey {
        (*self.elgamal.pubkey()).into()
    }
}

// ---------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------

/// One transaction's worth of instructions.
pub struct Step {
    pub label: &'static str,
    /// Keypairs (besides the fee payer and the token account owner) that must
    /// sign this transaction: freshly generated proof/record accounts.
    pub extra_signers: Vec<Keypair>,
    pub instructions: Vec<Instruction>,
}

/// Submit `setup` in order, then `main`, then `cleanup`. Every step is signed
/// by the fee payer and the token account owner, plus its own `extra_signers`.
pub struct Plan {
    pub setup: Vec<Step>,
    pub main: Step,
    pub cleanup: Step,
}

impl Plan {
    pub fn steps(&self) -> impl Iterator<Item = &Step> {
        self.setup
            .iter()
            .chain(std::iter::once(&self.main))
            .chain(std::iter::once(&self.cleanup))
    }
}

pub struct TransferPlan {
    pub plan: Plan,
    /// Fee withheld from this transfer, priced in the current epoch.
    pub fee: u64,
    /// The transfer amount encrypted to the mint's auditor, exactly as carried
    /// in the instruction. Meaningful only if the mint has an auditor key.
    pub auditor_ciphertext_lo: PodElGamalCiphertext,
    pub auditor_ciphertext_hi: PodElGamalCiphertext,
}

// ---------------------------------------------------------------------------
// Reading confidential state
// ---------------------------------------------------------------------------

fn confidential_state(account_data: &[u8]) -> Result<(Account, ConfidentialTransferAccount)> {
    let account = StateWithExtensions::<Account>::unpack(account_data)?;
    let state = *account
        .get_extension::<ConfidentialTransferAccount>()
        .map_err(|_| Error::MissingExtension(ExtensionType::ConfidentialTransferAccount))?;
    Ok((account.base, state))
}

fn elgamal_ciphertext(pod: PodElGamalCiphertext) -> Result<ElGamalCiphertext> {
    ElGamalCiphertext::try_from(pod).map_err(conf)
}

fn ae_ciphertext(pod: PodAeCiphertext) -> Result<AeCiphertext> {
    AeCiphertext::try_from(pod).map_err(conf)
}

/// Owner's view of the available balance, via the AES-cached copy.
pub fn decrypt_available_balance(
    state: &ConfidentialTransferAccount,
    keys: &ConfidentialKeys,
) -> Result<u64> {
    keys.aes
        .decrypt(&ae_ciphertext(state.decryptable_available_balance)?)
        .ok_or_else(|| conf("available balance does not decrypt under this AES key"))
}

/// Owner's view of the pending balance: both halves decrypted with the ElGamal
/// secret key and recombined as `lo + hi * 2^16`.
pub fn decrypt_pending_balance(
    state: &ConfidentialTransferAccount,
    keys: &ConfidentialKeys,
) -> Result<u64> {
    let secret = keys.elgamal.secret();
    let lo = secret
        .decrypt_u32(&elgamal_ciphertext(state.pending_balance_lo)?)
        .ok_or_else(|| conf("pending_balance_lo does not decrypt"))?;
    let hi = secret
        .decrypt_u32(&elgamal_ciphertext(state.pending_balance_hi)?)
        .ok_or_else(|| conf("pending_balance_hi does not decrypt"))?;
    hi.checked_shl(PENDING_BALANCE_LO_BIT_LENGTH)
        .and_then(|shifted| shifted.checked_add(lo))
        .ok_or_else(|| conf("pending balance overflow"))
}

/// What an auditor learns from a confidential transfer: the amount, decrypted
/// from the copy addressed to the auditor's ElGamal key.
pub fn decrypt_auditor_amount(
    auditor: &ElGamalKeypair,
    ciphertext_lo: PodElGamalCiphertext,
    ciphertext_hi: PodElGamalCiphertext,
) -> Result<u64> {
    let secret = auditor.secret();
    let lo = secret
        .decrypt_u32(&elgamal_ciphertext(ciphertext_lo)?)
        .ok_or_else(|| conf("auditor ciphertext (lo) does not decrypt"))?;
    let hi = secret
        .decrypt_u32(&elgamal_ciphertext(ciphertext_hi)?)
        .ok_or_else(|| conf("auditor ciphertext (hi) does not decrypt"))?;
    hi.checked_shl(PENDING_BALANCE_LO_BIT_LENGTH)
        .and_then(|shifted| shifted.checked_add(lo))
        .ok_or_else(|| conf("auditor amount overflow"))
}

/// Try to read an account's available balance with an arbitrary ElGamal key.
/// Succeeds only for the account owner's key; used to show that the auditor key
/// does *not* open balances.
pub fn decrypt_available_balance_with_elgamal(
    state: &ConfidentialTransferAccount,
    keypair: &ElGamalKeypair,
) -> Option<u64> {
    let ciphertext = ElGamalCiphertext::try_from(state.available_balance).ok()?;
    keypair.secret().decrypt_u32(&ciphertext)
}

/// Everything the owner can learn about their confidential balance, decrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfidentialStateView {
    pub approved: bool,
    /// Credits waiting for `ApplyPendingBalance`.
    pub pending: u64,
    /// Spendable balance, read from the AES-encrypted cached copy.
    pub available: u64,
    /// The same balance read by decrypting the real on-chain ciphertext with the
    /// ElGamal key. Equal to `available` unless the cache is stale.
    pub available_by_elgamal: u64,
    pub pending_credit_counter: u64,
}

pub fn view<C: ChainReader + ?Sized>(
    chain: &C,
    token_account: &Pubkey,
    keys: &ConfidentialKeys,
) -> Result<ConfidentialStateView> {
    let state = fetch_state(chain, token_account)?;
    let available_by_elgamal = keys
        .elgamal
        .secret()
        .decrypt_u32(&elgamal_ciphertext(state.available_balance)?)
        .ok_or_else(|| conf("available_balance does not decrypt under this ElGamal key"))?;
    Ok(ConfidentialStateView {
        approved: bool::from(state.approved),
        pending: decrypt_pending_balance(&state, keys)?,
        available: decrypt_available_balance(&state, keys)?,
        available_by_elgamal,
        pending_credit_counter: u64::from(state.pending_balance_credit_counter),
    })
}

pub fn fetch_state<C: ChainReader + ?Sized>(
    chain: &C,
    token_account: &Pubkey,
) -> Result<ConfidentialTransferAccount> {
    let data = require_account_data(chain, token_account)?;
    Ok(confidential_state(&data)?.1)
}

// ---------------------------------------------------------------------------
// Configure / approve / deposit / apply
// ---------------------------------------------------------------------------

/// `Reallocate` + `ConfigureAccount`: opt a token account into confidential
/// transfers.
///
/// **Owner-only.** `ConfigureAccount` is validated against the token account's
/// owner (or multisig); the permanent delegate, the freeze authority and the
/// ATA payer have no standing here. That is the difference from ATA creation,
/// which anyone can do for anyone.
///
/// `Reallocate` is required because an ATA is sized only for the extensions the
/// *mint* mandates on accounts, and `ConfidentialTransferAccount` (and, on a fee
/// mint, `ConfidentialTransferFeeAmount`) is not among them. `payer` funds the
/// extra rent.
///
/// Signers: `payer` and `owner`. The `PubkeyValidity` proof is tiny and rides in
/// the same transaction, immediately after `ConfigureAccount`.
pub fn configure_account<C: ChainReader + ?Sized>(
    chain: &C,
    payer: &Pubkey,
    owner: &Pubkey,
    token_account: &Pubkey,
    keys: &ConfidentialKeys,
) -> Result<Vec<Instruction>> {
    let account_data = require_account_data(chain, token_account)?;
    let account = StateWithExtensions::<Account>::unpack(&account_data)?;
    let mint = account.base.mint;
    let present = account.get_extension_types()?;

    let mint_data = require_account_data(chain, &mint)?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data)?;
    mint_state
        .get_extension::<ConfidentialTransferMint>()
        .map_err(|_| Error::MissingExtension(ExtensionType::ConfidentialTransferMint))?;

    let mut needed = vec![ExtensionType::ConfidentialTransferAccount];
    if mint_state.get_extension::<TransferFeeConfig>().is_ok() {
        needed.push(ExtensionType::ConfidentialTransferFeeAmount);
    }
    let missing: Vec<ExtensionType> = needed
        .into_iter()
        .filter(|ext| !present.contains(ext))
        .collect();

    let token_program = token_program_id();
    let mut ixs = Vec::new();
    if !missing.is_empty() {
        ixs.push(reallocate(
            &token_program,
            token_account,
            payer,
            owner,
            &[],
            &missing,
        )?);
    }

    let proof_data = build_pubkey_validity_proof_data(&keys.elgamal).map_err(proof)?;
    let decryptable_zero_balance: PodAeCiphertext = keys.aes.encrypt(0).into();
    ixs.extend(ct::configure_account(
        &token_program,
        token_account,
        &mint,
        &decryptable_zero_balance,
        MAXIMUM_PENDING_BALANCE_CREDIT_COUNTER,
        owner,
        &[],
        // `1`: the proof instruction is the very next one in the transaction.
        ProofLocation::InstructionOffset(NonZeroI8::new(1).expect("1 != 0"), &proof_data),
    )?);
    Ok(ixs)
}

/// `ApproveAccount`: the manual-approval gate. Signed by the mint's
/// confidential-transfer authority. Until this runs, the account cannot receive
/// confidential credits (deposit or transfer).
pub fn approve_account(
    token_account: &Pubkey,
    mint: &Pubkey,
    confidential_transfer_authority: &Pubkey,
) -> Result<Instruction> {
    Ok(ct::approve_account(
        &token_program_id(),
        token_account,
        mint,
        confidential_transfer_authority,
        &[],
    )?)
}

/// `DepositConfidentialTokens`: move `amount` of the public balance into the
/// account's *pending* confidential balance. The amount is visible on chain;
/// only what happens next is hidden.
pub fn deposit<C: ChainReader + ?Sized>(
    chain: &C,
    token_account: &Pubkey,
    owner: &Pubkey,
    amount: u64,
) -> Result<Instruction> {
    let account_data = require_account_data(chain, token_account)?;
    let mint = StateWithExtensions::<Account>::unpack(&account_data)?
        .base
        .mint;
    let mint_data = require_account_data(chain, &mint)?;
    let decimals = StateWithExtensions::<Mint>::unpack(&mint_data)?
        .base
        .decimals;

    Ok(ct::deposit(
        &token_program_id(),
        token_account,
        &mint,
        amount,
        decimals,
        owner,
        &[],
    )?)
}

/// `ApplyPendingBalance`: fold the pending balance into the available balance.
///
/// Only the available balance can be spent, transferred or withdrawn; pending
/// credits (from deposits and incoming transfers) are invisible to those
/// instructions until applied. The owner decrypts the pending ciphertexts,
/// computes the new total and re-encrypts it under the AES key; the program
/// checks `expected_pending_balance_credit_counter` so a credit that arrives
/// between the owner's read and this instruction is not silently dropped.
pub fn apply_pending_balance<C: ChainReader + ?Sized>(
    chain: &C,
    token_account: &Pubkey,
    owner: &Pubkey,
    keys: &ConfidentialKeys,
) -> Result<Instruction> {
    let data = require_account_data(chain, token_account)?;
    let (_, state) = confidential_state(&data)?;

    let pending = decrypt_pending_balance(&state, keys)?;
    let available = decrypt_available_balance(&state, keys)?;
    let new_available = available
        .checked_add(pending)
        .ok_or_else(|| conf("available balance overflow"))?;
    let new_decryptable: PodAeCiphertext = keys.aes.encrypt(new_available).into();

    Ok(ct::apply_pending_balance(
        &token_program_id(),
        token_account,
        u64::from(state.pending_balance_credit_counter),
        &new_decryptable,
        owner,
        &[],
    )?)
}

// ---------------------------------------------------------------------------
// Proof staging
// ---------------------------------------------------------------------------

fn compute_budget(units: u32) -> Instruction {
    ComputeBudgetInstruction::set_compute_unit_limit(units)
}

/// Verify one proof into a fresh context state account.
///
/// Returns the context account's address and the steps that create it. Small
/// proofs are verified straight from instruction data; large ones are first
/// written to a Record account, verified from there, and the Record account is
/// closed again.
#[allow(clippy::too_many_arguments)]
fn stage_proof<T, U>(
    payer: &Pubkey,
    authority: &Pubkey,
    kind: ProofInstruction,
    label: &'static str,
    proof_data: &T,
    rent_exempt: RentFn<'_>,
    steps: &mut Vec<Step>,
    contexts: &mut Vec<Pubkey>,
) -> Pubkey
where
    T: Pod + ZkProofData<U>,
    U: Pod,
{
    let context_account = Keypair::new();
    let context_address = context_account.pubkey();
    let context_len = size_of::<ProofContextState<U>>();
    let create_context = system_instruction::create_account(
        payer,
        &context_address,
        rent_exempt(context_len),
        context_len as u64,
        &solana_zk_elgamal_proof_interface::id(),
    );
    let context_info = ContextStateInfo {
        context_state_account: &context_address,
        context_state_authority: authority,
    };

    if size_of::<T>() <= INLINE_PROOF_LIMIT {
        steps.push(Step {
            label,
            extra_signers: vec![context_account],
            instructions: vec![
                compute_budget(PROOF_VERIFY_COMPUTE_UNITS),
                create_context,
                kind.encode_verify_proof(Some(context_info), proof_data),
            ],
        });
    } else {
        let record_account = Keypair::new();
        let record_address = record_account.pubkey();
        let bytes = bytemuck::bytes_of(proof_data);

        steps.push(Step {
            label: "record: create",
            extra_signers: vec![record_account],
            instructions: vec![
                record::create(payer, &record_address, bytes.len(), rent_exempt),
                record::initialize(&record_address, authority),
            ],
        });
        for (offset, chunk) in record::chunks(bytes) {
            steps.push(Step {
                label: "record: write proof",
                extra_signers: vec![],
                instructions: vec![record::write(&record_address, authority, offset, chunk)],
            });
        }
        steps.push(Step {
            label,
            extra_signers: vec![context_account],
            instructions: vec![
                compute_budget(PROOF_VERIFY_COMPUTE_UNITS),
                create_context,
                kind.encode_verify_proof_from_account(
                    Some(context_info),
                    &record_address,
                    record::RECORD_HEADER_LEN as u32,
                ),
            ],
        });
        steps.push(Step {
            label: "record: close",
            extra_signers: vec![],
            instructions: vec![record::close(&record_address, authority, payer)],
        });
    }

    contexts.push(context_address);
    context_address
}

fn close_contexts(payer: &Pubkey, authority: &Pubkey, contexts: &[Pubkey]) -> Step {
    Step {
        label: "close proof context accounts",
        extra_signers: vec![],
        instructions: contexts
            .iter()
            .map(|context| {
                close_context_state(
                    ContextStateInfo {
                        context_state_account: context,
                        context_state_authority: authority,
                    },
                    payer,
                )
            })
            .collect(),
    }
}

// ---------------------------------------------------------------------------
// Confidential transfer
// ---------------------------------------------------------------------------

/// Plan a confidential transfer of `amount` from `source` to `destination`.
///
/// The fee is computed from the mint's schedule in the current epoch (the
/// processor does the same with `Clock::epoch`) and proven, not trusted.
#[allow(clippy::too_many_arguments)]
pub fn plan_transfer<C: ChainReader + ?Sized>(
    chain: &C,
    payer: &Pubkey,
    owner: &Pubkey,
    source: &Pubkey,
    destination: &Pubkey,
    amount: u64,
    keys: &ConfidentialKeys,
    rent_exempt: RentFn<'_>,
) -> Result<TransferPlan> {
    let source_data = require_account_data(chain, source)?;
    let (source_base, source_state) = confidential_state(&source_data)?;
    let mint = source_base.mint;

    let destination_data = require_account_data(chain, destination)?;
    let (destination_base, destination_state) = confidential_state(&destination_data)?;
    if destination_base.mint != mint {
        return Err(conf("source and destination belong to different mints"));
    }

    let mint_data = require_account_data(chain, &mint)?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data)?;
    let confidential_mint = mint_state
        .get_extension::<ConfidentialTransferMint>()
        .map_err(|_| Error::MissingExtension(ExtensionType::ConfidentialTransferMint))?;
    let confidential_fee = mint_state
        .get_extension::<ConfidentialTransferFeeConfig>()
        .map_err(|_| Error::MissingExtension(ExtensionType::ConfidentialTransferFeeConfig))?;
    let fee_config = mint_state
        .get_extension::<TransferFeeConfig>()
        .map_err(|_| Error::MissingExtension(ExtensionType::TransferFeeConfig))?;

    let epoch = chain.current_epoch();
    let fee_rate = fee_config.get_epoch_fee(epoch);
    let fee = fee_config
        .calculate_epoch_fee(epoch, amount)
        .ok_or(Error::FeeOverflow)?;

    let auditor: Option<PodElGamalPubkey> = confidential_mint.auditor_elgamal_pubkey.into();
    let auditor = auditor
        .map(|pod| ElGamalPubkey::try_from(pod).map_err(conf))
        .transpose()?;
    let destination_pubkey =
        ElGamalPubkey::try_from(destination_state.elgamal_pubkey).map_err(conf)?;
    let withdraw_withheld_pubkey =
        ElGamalPubkey::try_from(confidential_fee.withdraw_withheld_authority_elgamal_pubkey)
            .map_err(conf)?;

    let available = decrypt_available_balance(&source_state, keys)?;
    let new_available = available.checked_sub(amount).ok_or_else(|| {
        conf("transfer exceeds the available balance (apply pending balance first?)")
    })?;
    let new_decryptable: PodAeCiphertext = keys.aes.encrypt(new_available).into();

    let proofs = transfer_with_fee_split_proof_data(
        &elgamal_ciphertext(source_state.available_balance)?,
        &ae_ciphertext(source_state.decryptable_available_balance)?,
        amount,
        &keys.elgamal,
        &keys.aes,
        &destination_pubkey,
        auditor.as_ref(),
        &withdraw_withheld_pubkey,
        u16::from(fee_rate.transfer_fee_basis_points),
        u64::from(fee_rate.maximum_fee),
    )
    .map_err(proof)?;

    let mut setup = Vec::new();
    let mut contexts = Vec::new();

    let equality = stage_proof(
        payer,
        owner,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        "verify: ciphertext-commitment equality",
        &proofs.equality_proof_data,
        rent_exempt,
        &mut setup,
        &mut contexts,
    );
    let amount_validity = stage_proof(
        payer,
        owner,
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
        "verify: transfer-amount ciphertext validity",
        &proofs
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .proof_data,
        rent_exempt,
        &mut setup,
        &mut contexts,
    );
    let fee_sigma = stage_proof(
        payer,
        owner,
        ProofInstruction::VerifyPercentageWithCap,
        "verify: fee percentage-with-cap",
        &proofs.percentage_with_cap_proof_data,
        rent_exempt,
        &mut setup,
        &mut contexts,
    );
    let fee_validity = stage_proof(
        payer,
        owner,
        ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity,
        "verify: fee ciphertext validity",
        &proofs.fee_ciphertext_validity_proof_data,
        rent_exempt,
        &mut setup,
        &mut contexts,
    );
    let range = stage_proof(
        payer,
        owner,
        ProofInstruction::VerifyBatchedRangeProofU256,
        "verify: 256-bit range proof",
        &proofs.range_proof_data,
        rent_exempt,
        &mut setup,
        &mut contexts,
    );

    let auditor_lo = proofs
        .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
        .ciphertext_lo;
    let auditor_hi = proofs
        .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
        .ciphertext_hi;

    let mut instructions = vec![compute_budget(CONFIDENTIAL_INSTRUCTION_COMPUTE_UNITS)];
    instructions.extend(ct::transfer_with_fee(
        &token_program_id(),
        source,
        &mint,
        destination,
        &new_decryptable,
        &auditor_lo,
        &auditor_hi,
        owner,
        &[],
        ProofLocation::ContextStateAccount(&equality),
        ProofLocation::ContextStateAccount(&amount_validity),
        ProofLocation::ContextStateAccount(&fee_sigma),
        ProofLocation::ContextStateAccount(&fee_validity),
        ProofLocation::ContextStateAccount(&range),
    )?);

    Ok(TransferPlan {
        plan: Plan {
            setup,
            main: Step {
                label: "confidential transfer (with fee)",
                extra_signers: vec![],
                instructions,
            },
            cleanup: close_contexts(payer, owner, &contexts),
        },
        fee,
        auditor_ciphertext_lo: auditor_lo,
        auditor_ciphertext_hi: auditor_hi,
    })
}

// ---------------------------------------------------------------------------
// Withdraw
// ---------------------------------------------------------------------------

/// Plan a `Withdraw` of `amount` from the available confidential balance back to
/// the public balance.
///
/// The amount leaves the encrypted domain, so it is visible on chain. Only the
/// *available* balance counts: if a deposit or incoming transfer is still
/// pending, run [`apply_pending_balance`] first or this fails with "not enough
/// funds" before any proof is generated.
pub fn plan_withdraw<C: ChainReader + ?Sized>(
    chain: &C,
    payer: &Pubkey,
    owner: &Pubkey,
    token_account: &Pubkey,
    amount: u64,
    keys: &ConfidentialKeys,
    rent_exempt: RentFn<'_>,
) -> Result<Plan> {
    let data = require_account_data(chain, token_account)?;
    let (base, state) = confidential_state(&data)?;
    let mint = base.mint;
    let mint_data = require_account_data(chain, &mint)?;
    let decimals = StateWithExtensions::<Mint>::unpack(&mint_data)?
        .base
        .decimals;

    let available = decrypt_available_balance(&state, keys)?;
    let new_available = available.checked_sub(amount).ok_or_else(|| {
        conf("withdraw exceeds the available balance (apply pending balance first?)")
    })?;
    let new_decryptable: PodAeCiphertext = keys.aes.encrypt(new_available).into();

    let proofs = withdraw_proof_data(
        &elgamal_ciphertext(state.available_balance)?,
        available,
        amount,
        &keys.elgamal,
    )
    .map_err(proof)?;

    let mut setup = Vec::new();
    let mut contexts = Vec::new();
    let equality = stage_proof(
        payer,
        owner,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        "verify: ciphertext-commitment equality",
        &proofs.equality_proof_data,
        rent_exempt,
        &mut setup,
        &mut contexts,
    );
    let range = stage_proof(
        payer,
        owner,
        ProofInstruction::VerifyBatchedRangeProofU64,
        "verify: 64-bit range proof",
        &proofs.range_proof_data,
        rent_exempt,
        &mut setup,
        &mut contexts,
    );

    let mut instructions = vec![compute_budget(CONFIDENTIAL_INSTRUCTION_COMPUTE_UNITS)];
    instructions.extend(ct::withdraw(
        &token_program_id(),
        token_account,
        &mint,
        amount,
        decimals,
        &new_decryptable,
        owner,
        &[],
        ProofLocation::ContextStateAccount(&equality),
        ProofLocation::ContextStateAccount(&range),
    )?);

    Ok(Plan {
        setup,
        main: Step {
            label: "withdraw confidential tokens",
            extra_signers: vec![],
            instructions,
        },
        cleanup: close_contexts(payer, owner, &contexts),
    })
}
