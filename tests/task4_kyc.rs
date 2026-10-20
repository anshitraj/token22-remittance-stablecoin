//! Task 4: the freeze authority thaws individual accounts after KYC, separately
//! from any mint-level default-state change.

mod common;

use {
    common::*,
    remittance_stablecoin::token_program_id,
    remittance_stablecoin::{Error, kyc, state, transfer},
    solana_signer::Signer,
    spl_token_2022_interface::{
        error::TokenError,
        instruction::{mint_to_checked, thaw_account},
        state::AccountState,
    },
};

#[test]
fn frozen_accounts_can_neither_receive_nor_send() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let alice = env.wallet();
    let bob = env.wallet();

    let alice_ata = env.onboard(&issuer, &mint.pubkey(), &alice.pubkey(), 100 * ONE);
    let bob_ata = env.create_ata_for(&bob.pubkey(), &mint.pubkey()); // still frozen: no KYC yet

    // Minting into a frozen account fails...
    let mint_ix = mint_to_checked(
        &token_program_id(),
        &mint.pubkey(),
        &bob_ata,
        &issuer.mint_authority.pubkey(),
        &[],
        ONE,
        DECIMALS,
    )
    .unwrap();
    let failed = env.send_err(&[mint_ix], &[&issuer.mint_authority]);
    assert_token_error(&failed, TokenError::AccountFrozen);

    // ...and so does a transfer into it.
    let ix =
        transfer::transfer_with_fee(&env, &alice_ata, &bob_ata, &alice.pubkey(), 10 * ONE).unwrap();
    let failed = env.send_err(&[ix], &[&alice]);
    assert_token_error(&failed, TokenError::AccountFrozen);
}

#[test]
fn freeze_authority_thaws_one_account_and_only_that_account() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let mint_key = mint.pubkey();

    let alice = env.wallet();
    let bob = env.wallet();
    let alice_ata = env.create_ata_for(&alice.pubkey(), &mint_key);
    let bob_ata = env.create_ata_for(&bob.pubkey(), &mint_key);

    // KYC clears Alice.
    let thaw = kyc::thaw_after_kyc(&env, &alice_ata, &issuer.freeze_authority.pubkey()).unwrap();
    env.send_ok(&[thaw], &[&issuer.freeze_authority]);

    assert_eq!(
        state::fetch_account(&env, &alice_ata).unwrap().state,
        AccountState::Initialized
    );
    assert_eq!(
        state::fetch_account(&env, &bob_ata).unwrap().state,
        AccountState::Frozen,
        "Bob has not been cleared"
    );

    // The mint's default did not move: an account created now is still frozen.
    let carol = env.wallet();
    let carol_ata = env.create_ata_for(&carol.pubkey(), &mint_key);
    assert_eq!(
        state::fetch_account(&env, &carol_ata).unwrap().state,
        AccountState::Frozen
    );
    assert_eq!(
        state::fetch_mint(&env, &mint_key)
            .unwrap()
            .default_account_state,
        Some(AccountState::Frozen)
    );
}

#[test]
fn nobody_but_the_freeze_authority_can_thaw() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let mint_key = mint.pubkey();

    let alice = env.wallet();
    let alice_ata = env.create_ata_for(&alice.pubkey(), &mint_key);

    // Off-chain guard: wrong authority is named in the error.
    let err = kyc::thaw_after_kyc(&env, &alice_ata, &alice.pubkey()).unwrap_err();
    assert!(matches!(err, Error::WrongAuthority { .. }), "{err}");

    // On-chain: the account owner, the mint authority and the metadata
    // authority all fail when they try anyway.
    for impostor in [
        &alice,
        &issuer.mint_authority,
        &issuer.metadata_authority,
        &issuer.permanent_delegate,
    ] {
        let ix = thaw_account(
            &token_program_id(),
            &alice_ata,
            &mint_key,
            &impostor.pubkey(),
            &[],
        )
        .unwrap();
        let failed = env.send_err(&[ix], &[impostor]);
        assert_token_error(&failed, TokenError::OwnerMismatch);
    }
    assert_eq!(
        state::fetch_account(&env, &alice_ata).unwrap().state,
        AccountState::Frozen
    );
}

#[test]
fn thawing_a_thawed_account_is_caught_before_the_chain_sees_it() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let alice = env.wallet();
    let alice_ata = env.onboard(&issuer, &mint.pubkey(), &alice.pubkey(), 0);

    let err = kyc::thaw_after_kyc(&env, &alice_ata, &issuer.freeze_authority.pubkey()).unwrap_err();
    assert!(
        matches!(err, Error::NotFrozen(account) if account == alice_ata),
        "{err}"
    );
}

/// The mint-level switch is a different instruction with a different blast
/// radius: it decides how *future* accounts are born and touches no existing
/// account.
#[test]
fn changing_the_default_state_does_not_thaw_existing_accounts() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let mint_key = mint.pubkey();

    let early = env.wallet();
    let early_ata = env.create_ata_for(&early.pubkey(), &mint_key); // born frozen

    // Only the freeze authority may flip the default.
    let intruder = env.wallet();
    let ix =
        kyc::set_default_account_state(&mint_key, &intruder.pubkey(), AccountState::Initialized)
            .unwrap();
    let failed = env.send_err(&[ix], &[&intruder]);
    assert_token_error(&failed, TokenError::OwnerMismatch);

    // Freeze authority opens the gates.
    let ix = kyc::set_default_account_state(
        &mint_key,
        &issuer.freeze_authority.pubkey(),
        AccountState::Initialized,
    )
    .unwrap();
    env.send_ok(&[ix], &[&issuer.freeze_authority]);
    assert_eq!(
        state::fetch_mint(&env, &mint_key)
            .unwrap()
            .default_account_state,
        Some(AccountState::Initialized)
    );

    // A new account is born usable...
    let late = env.wallet();
    let late_ata = env.create_ata_for(&late.pubkey(), &mint_key);
    assert_eq!(
        state::fetch_account(&env, &late_ata).unwrap().state,
        AccountState::Initialized
    );
    // ...but the account created earlier is still frozen: per-account thaw is the only way out.
    assert_eq!(
        state::fetch_account(&env, &early_ata).unwrap().state,
        AccountState::Frozen
    );

    // Close the gates again.
    let ix = kyc::set_default_account_state(
        &mint_key,
        &issuer.freeze_authority.pubkey(),
        AccountState::Frozen,
    )
    .unwrap();
    env.send_ok(&[ix], &[&issuer.freeze_authority]);
    let newest = env.wallet();
    let newest_ata = env.create_ata_for(&newest.pubkey(), &mint_key);
    assert_eq!(
        state::fetch_account(&env, &newest_ata).unwrap().state,
        AccountState::Frozen
    );
    // Accounts that were born open stay open.
    assert_eq!(
        state::fetch_account(&env, &late_ata).unwrap().state,
        AccountState::Initialized
    );
}

#[test]
fn freeze_authority_can_refreeze_after_a_sanctions_hit() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let alice = env.wallet();
    let bob = env.wallet();
    let alice_ata = env.onboard(&issuer, &mint.pubkey(), &alice.pubkey(), 50 * ONE);
    let bob_ata = env.onboard(&issuer, &mint.pubkey(), &bob.pubkey(), 0);

    let ix = kyc::freeze(&env, &alice_ata, &issuer.freeze_authority.pubkey()).unwrap();
    env.send_ok(&[ix], &[&issuer.freeze_authority]);
    assert_eq!(
        state::fetch_account(&env, &alice_ata).unwrap().state,
        AccountState::Frozen
    );

    // Alice can no longer move her funds.
    let ix =
        transfer::transfer_with_fee(&env, &alice_ata, &bob_ata, &alice.pubkey(), 10 * ONE).unwrap();
    let failed = env.send_err(&[ix], &[&alice]);
    assert_token_error(&failed, TokenError::AccountFrozen);

    // And she cannot undo it herself.
    let own_thaw = thaw_account(
        &token_program_id(),
        &alice_ata,
        &mint.pubkey(),
        &alice.pubkey(),
        &[],
    )
    .unwrap();
    assert!(env.send(&[own_thaw], &[&alice]).is_err());
}
