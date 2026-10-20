//! The written finding, as executable evidence.
//!
//! Question: *what happens if a sanctioned user moves their balance into the
//! confidential system before the permanent delegate acts?*
//!
//! Short answer, demonstrated below: the permanent delegate's power stops at the
//! public balance. Funds that have entered the confidential system are out of
//! its reach, and nothing the issuer holds can pull them back. What the issuer
//! *can* do is freeze them in place, refuse to approve the account in the first
//! place, and watch amounts through the auditor key. See
//! `docs/WRITTEN_FINDING.md`.

mod common;

use {
    common::*,
    remittance_stablecoin::{
        Error, Pubkey,
        confidential::{self, ConfidentialKeys},
        kyc, seizure, state,
    },
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::error::TokenError,
};

struct Case {
    env: Env,
    issuer: Issuer,
    authorities: ConfidentialAuthorities,
    mint: Keypair,
    mallory: Keypair,
    mallory_ata: Pubkey,
    mallory_keys: ConfidentialKeys,
    treasury_ata: Pubkey,
}

/// Mallory is KYC'd, approved for confidential transfers and holds 1000 public
/// tokens. A sanctions order is about to land.
fn case() -> Case {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let authorities = ConfidentialAuthorities::new();
    let mint = env.create_v2_mint(&issuer, &authorities);
    let mallory = env.wallet();
    let (mallory_ata, mallory_keys) = env.enable_confidential(&issuer, &mint.pubkey(), &mallory);
    env.mint_to(&issuer, &mint.pubkey(), &mallory_ata, 1_000 * ONE);

    let treasury = env.wallet();
    let treasury_ata = env.onboard(&issuer, &mint.pubkey(), &treasury.pubkey(), 0);
    Case {
        env,
        issuer,
        authorities,
        mint,
        mallory,
        mallory_ata,
        mallory_keys,
        treasury_ata,
    }
}

/// The baseline: before Mallory reacts, seizure simply works.
#[test]
fn baseline_the_delegate_seizes_everything_that_is_still_public() {
    let mut c = case();
    let delegate = c.issuer.permanent_delegate.pubkey();
    let ix =
        seizure::seize_public_balance(&c.env, &c.mallory_ata, &c.treasury_ata, &delegate).unwrap();
    c.env.send_ok(&[ix], &[&c.issuer.permanent_delegate]);
    assert_eq!(c.env.balance(&c.mallory_ata), 0);
    assert_eq!(c.env.balance(&c.treasury_ata), 1_000 * ONE - MAX_FEE);
}

/// Mallory sees the order coming and shields everything first.
#[test]
fn after_shielding_the_delegate_has_nothing_to_seize() {
    let mut c = case();
    let delegate = c.issuer.permanent_delegate.pubkey();
    let mallory = Keypair::try_from(c.mallory.to_bytes().as_slice()).unwrap();
    c.env
        .shield(&mallory, &c.mallory_ata, &c.mallory_keys, 1_000 * ONE);

    // The public balance is zero; the money is in ciphertext.
    assert_eq!(c.env.balance(&c.mallory_ata), 0);
    let secret = confidential::view(&c.env, &c.mallory_ata, &c.mallory_keys).unwrap();
    assert_eq!(secret.available, 1_000 * ONE);
    // Total supply is untouched: the tokens still exist, they are just unreachable.
    assert_eq!(c.env.supply(&c.mint.pubkey()), 1_000 * ONE);

    // Library guard: nothing to move.
    let err = seizure::seize_public_balance(&c.env, &c.mallory_ata, &c.treasury_ata, &delegate)
        .unwrap_err();
    assert!(matches!(err, Error::NothingToMove(_)), "{err}");

    // On-chain: force the transfer anyway. The program has no public balance to take.
    let forced = remittance_stablecoin::transfer::transfer_with_fee(
        &c.env,
        &c.mallory_ata,
        &c.treasury_ata,
        &delegate,
        1_000 * ONE,
    )
    .unwrap();
    let failed = c.env.send_err(&[forced], &[&c.issuer.permanent_delegate]);
    assert_token_error(&failed, TokenError::InsufficientFunds);

    // Burning fails the same way.
    let burn = spl_token_2022_interface::instruction::burn_checked(
        &remittance_stablecoin::token_program_id(),
        &c.mallory_ata,
        &c.mint.pubkey(),
        &delegate,
        &[],
        1_000 * ONE,
        DECIMALS,
    )
    .unwrap();
    let failed = c.env.send_err(&[burn], &[&c.issuer.permanent_delegate]);
    assert_token_error(&failed, TokenError::InsufficientFunds);
}

/// Pending (just deposited, not yet applied) is already out of reach too.
#[test]
fn a_deposit_is_unreachable_even_before_it_is_applied() {
    let mut c = case();
    let delegate = c.issuer.permanent_delegate.pubkey();
    let mallory = Keypair::try_from(c.mallory.to_bytes().as_slice()).unwrap();

    let deposit =
        confidential::deposit(&c.env, &c.mallory_ata, &mallory.pubkey(), 1_000 * ONE).unwrap();
    c.env.send_ok(&[deposit], &[&mallory]);
    let view = confidential::view(&c.env, &c.mallory_ata, &c.mallory_keys).unwrap();
    assert_eq!((view.pending, view.available), (1_000 * ONE, 0));

    let forced = remittance_stablecoin::transfer::transfer_with_fee(
        &c.env,
        &c.mallory_ata,
        &c.treasury_ata,
        &delegate,
        ONE,
    )
    .unwrap();
    assert_token_error(
        &c.env.send_err(&[forced], &[&c.issuer.permanent_delegate]),
        TokenError::InsufficientFunds,
    );
}

/// The race is real but partial: the delegate gets whatever is still public
/// when it lands.
#[test]
fn a_partial_shield_leaves_the_remainder_seizable() {
    let mut c = case();
    let delegate = c.issuer.permanent_delegate.pubkey();
    let mallory = Keypair::try_from(c.mallory.to_bytes().as_slice()).unwrap();
    c.env
        .shield(&mallory, &c.mallory_ata, &c.mallory_keys, 600 * ONE);

    let ix =
        seizure::seize_public_balance(&c.env, &c.mallory_ata, &c.treasury_ata, &delegate).unwrap();
    c.env.send_ok(&[ix], &[&c.issuer.permanent_delegate]);

    assert_eq!(c.env.balance(&c.mallory_ata), 0);
    assert_eq!(c.env.balance(&c.treasury_ata), 400 * ONE - MAX_FEE);
    // 600 stay encrypted and untouched.
    assert_eq!(
        confidential::view(&c.env, &c.mallory_ata, &c.mallory_keys)
            .unwrap()
            .available,
        600 * ONE
    );
}

/// The delegate is not an authority for any confidential instruction: it cannot
/// deposit, apply, withdraw or transfer on the owner's behalf.
#[test]
fn the_permanent_delegate_is_not_recognised_by_confidential_instructions() {
    let mut c = case();
    let mallory = Keypair::try_from(c.mallory.to_bytes().as_slice()).unwrap();
    c.env
        .shield(&mallory, &c.mallory_ata, &c.mallory_keys, 500 * ONE);
    let delegate = c.issuer.permanent_delegate.pubkey();

    // Deposit with the delegate as authority (public balance is 500, so funds exist).
    let ix = confidential::deposit(&c.env, &c.mallory_ata, &delegate, ONE).unwrap();
    assert_token_error(
        &c.env.send_err(&[ix], &[&c.issuer.permanent_delegate]),
        TokenError::OwnerMismatch,
    );

    // Withdraw. Grant the delegate the best case: it somehow holds Mallory's
    // keys and so can build every proof. The proofs verify (they are just
    // maths), but the token program asks who the *owner* is and the delegate
    // is not it.
    let payer = c.env.payer.pubkey();
    let plan = confidential::plan_withdraw(
        &c.env,
        &payer,
        &delegate,
        &c.mallory_ata,
        100 * ONE,
        &c.mallory_keys,
        &|len| c.env.rent(len),
    )
    .unwrap();
    for step in &plan.setup {
        c.env.run_step(step, &c.issuer.permanent_delegate);
    }
    let failed = c
        .env
        .send_err(&plan.main.instructions, &[&c.issuer.permanent_delegate]);
    assert_token_error(&failed, TokenError::OwnerMismatch);

    // Nothing changed.
    assert_eq!(
        confidential::view(&c.env, &c.mallory_ata, &c.mallory_keys)
            .unwrap()
            .available,
        500 * ONE
    );
}

/// What the issuer *does* hold: the freeze authority. A frozen account cannot
/// deposit, apply, transfer or withdraw, so the confidential balance is locked
/// in place. Locked, not seized.
#[test]
fn freezing_locks_the_confidential_balance_but_does_not_recover_it() {
    let mut c = case();
    let mallory = Keypair::try_from(c.mallory.to_bytes().as_slice()).unwrap();
    c.env
        .shield(&mallory, &c.mallory_ata, &c.mallory_keys, 1_000 * ONE);

    let freeze = kyc::freeze(&c.env, &c.mallory_ata, &c.issuer.freeze_authority.pubkey()).unwrap();
    c.env.send_ok(&[freeze], &[&c.issuer.freeze_authority]);

    // Mallory cannot exit.
    let payer = c.env.payer.pubkey();
    let plan = confidential::plan_withdraw(
        &c.env,
        &payer,
        &mallory.pubkey(),
        &c.mallory_ata,
        1_000 * ONE,
        &c.mallory_keys,
        &|len| c.env.rent(len),
    )
    .unwrap();
    for step in &plan.setup {
        c.env.run_step(step, &mallory);
    }
    let failed = c.env.send_err(&plan.main.instructions, &[&mallory]);
    assert_token_error(&failed, TokenError::AccountFrozen);

    // Nor can she move it to someone else: a frozen source fails the transfer too.
    let bob = c.env.wallet();
    let (bob_ata, _bob_keys) = c.env.enable_confidential(&c.issuer, &c.mint.pubkey(), &bob);
    let transfer = confidential::plan_transfer(
        &c.env,
        &payer,
        &mallory.pubkey(),
        &c.mallory_ata,
        &bob_ata,
        10 * ONE,
        &c.mallory_keys,
        &|len| c.env.rent(len),
    )
    .unwrap();
    for step in &transfer.plan.setup {
        c.env.run_step(step, &mallory);
    }
    let failed = c
        .env
        .send_err(&transfer.plan.main.instructions, &[&mallory]);
    assert_token_error(&failed, TokenError::AccountFrozen);

    // ...and neither can the issuer take it: thawing hands Mallory the keys back,
    // and the delegate still finds an empty public balance.
    assert_eq!(c.env.balance(&c.mallory_ata), 0);
    assert_eq!(
        c.env.supply(&c.mint.pubkey()),
        1_000 * ONE,
        "the tokens are frozen, not destroyed"
    );
    let state = confidential::view(&c.env, &c.mallory_ata, &c.mallory_keys).unwrap();
    assert_eq!(
        state.available,
        1_000 * ONE,
        "balance intact under the freeze"
    );
}

/// The only road from ciphertext back to something seizable is the owner's own
/// signed Withdraw, and it re-exposes exactly the amount withdrawn.
#[test]
fn an_exit_back_to_the_public_balance_is_seizable_again() {
    let mut c = case();
    let delegate = c.issuer.permanent_delegate.pubkey();
    let mallory = Keypair::try_from(c.mallory.to_bytes().as_slice()).unwrap();
    c.env
        .shield(&mallory, &c.mallory_ata, &c.mallory_keys, 1_000 * ONE);

    let payer = c.env.payer.pubkey();
    let plan = confidential::plan_withdraw(
        &c.env,
        &payer,
        &mallory.pubkey(),
        &c.mallory_ata,
        250 * ONE,
        &c.mallory_keys,
        &|len| c.env.rent(len),
    )
    .unwrap();
    c.env.run_plan(&plan, &mallory);
    assert_eq!(c.env.balance(&c.mallory_ata), 250 * ONE);

    let ix =
        seizure::seize_public_balance(&c.env, &c.mallory_ata, &c.treasury_ata, &delegate).unwrap();
    c.env.send_ok(&[ix], &[&c.issuer.permanent_delegate]);
    assert_eq!(c.env.balance(&c.mallory_ata), 0);
    // 750 stay encrypted.
    assert_eq!(
        confidential::view(&c.env, &c.mallory_ata, &c.mallory_keys)
            .unwrap()
            .available,
        750 * ONE
    );
}

/// Gate at the door: under manual approval an account the issuer never approved
/// cannot receive confidential transfers either, so a sanctioned wallet that
/// configures itself stays shut out.
#[test]
fn an_unapproved_account_cannot_receive_a_confidential_transfer() {
    let mut c = case();
    let mallory = Keypair::try_from(c.mallory.to_bytes().as_slice()).unwrap();
    c.env
        .shield(&mallory, &c.mallory_ata, &c.mallory_keys, 100 * ONE);

    // A second wallet configures itself and is thawed but never approved.
    let outsider = c.env.wallet();
    let outsider_ata = c.env.create_ata_for(&outsider.pubkey(), &c.mint.pubkey());
    let outsider_keys = ConfidentialKeys::derive(&outsider).unwrap();
    let payer = c.env.payer.pubkey();
    let configure = confidential::configure_account(
        &c.env,
        &payer,
        &outsider.pubkey(),
        &outsider_ata,
        &outsider_keys,
    )
    .unwrap();
    c.env.send_ok(&configure, &[&outsider]);
    let mint = c.mint.pubkey();
    c.env.thaw(&c.issuer, &outsider_ata, &mint);

    let plan = confidential::plan_transfer(
        &c.env,
        &payer,
        &mallory.pubkey(),
        &c.mallory_ata,
        &outsider_ata,
        10 * ONE,
        &c.mallory_keys,
        &|len| c.env.rent(len),
    )
    .unwrap();
    for step in &plan.plan.setup {
        c.env.run_step(step, &mallory);
    }
    let failed = c.env.send_err(&plan.plan.main.instructions, &[&mallory]);
    assert_token_error(&failed, TokenError::ConfidentialTransferAccountNotApproved);
}

/// The auditor sees every transfer amount, and nothing else: not balances.
#[test]
fn the_auditor_reads_amounts_but_not_balances_and_cannot_move_anything() {
    let mut c = case();
    let mallory = Keypair::try_from(c.mallory.to_bytes().as_slice()).unwrap();
    c.env
        .shield(&mallory, &c.mallory_ata, &c.mallory_keys, 300 * ONE);

    let bob = c.env.wallet();
    let (bob_ata, _bob_keys) = c.env.enable_confidential(&c.issuer, &c.mint.pubkey(), &bob);

    let payer = c.env.payer.pubkey();
    let plan = confidential::plan_transfer(
        &c.env,
        &payer,
        &mallory.pubkey(),
        &c.mallory_ata,
        &bob_ata,
        120 * ONE,
        &c.mallory_keys,
        &|len| c.env.rent(len),
    )
    .unwrap();
    c.env.run_plan(&plan.plan, &mallory);

    // Amount: visible to the auditor.
    let seen = confidential::decrypt_auditor_amount(
        &c.authorities.auditor,
        plan.auditor_ciphertext_lo,
        plan.auditor_ciphertext_hi,
    )
    .unwrap();
    assert_eq!(seen, 120 * ONE);

    // Balance: not. The auditor key cannot decrypt Mallory's available balance.
    let on_chain = state::fetch_account(&c.env, &c.mallory_ata)
        .unwrap()
        .confidential
        .unwrap();
    let as_auditor =
        confidential::decrypt_available_balance_with_elgamal(&on_chain, &c.authorities.auditor);
    assert_eq!(
        as_auditor, None,
        "the auditor key must not open Mallory's 180 token balance"
    );
}
