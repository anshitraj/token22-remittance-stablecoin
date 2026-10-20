//! Task 5: re-issue the mint with a PermanentDelegate (seizure authority) and
//! confidential transfers with `approve_policy = manual`.
//!
//! Confidential transfers cannot be added to a live mint, so the "upgrade" is a
//! new mint that carries the v1 extension set forward.

mod common;

use {
    common::*,
    remittance_stablecoin::{
        Error, accounts::ata_address, mint, seizure, state, token_program_id, transfer,
    },
    solana_signer::Signer,
    spl_token_2022_interface::{
        error::TokenError,
        extension::{ExtensionType, confidential_transfer::instruction as ct_ix},
        instruction::{burn_checked, close_account},
        state::AccountState,
    },
};

#[test]
fn reissued_mint_carries_the_v1_extension_set_forward_and_adds_three() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let keys = ConfidentialAuthorities::new();
    let mint = env.create_v2_mint(&issuer, &keys);
    let view = state::fetch_mint(&env, &mint.pubkey()).unwrap();

    // Everything v1 had...
    for ext in mint::v1_extensions() {
        assert!(
            view.extensions.contains(&ext),
            "{ext:?} was not carried forward"
        );
    }
    // ...plus the three additions.
    for ext in [
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialTransferFeeConfig,
    ] {
        assert!(view.extensions.contains(&ext), "{ext:?} missing");
    }
    assert_eq!(
        view.extensions.len(),
        mint::v2_extensions().len() + 1,
        "+ TokenMetadata"
    );

    // The carried-forward configuration is identical, not merely present.
    let fee = view.transfer_fee.as_ref().unwrap();
    assert_eq!(
        (fee.newer.basis_points, fee.newer.maximum_fee),
        (FEE_BPS, MAX_FEE)
    );
    assert_eq!(view.default_account_state, Some(AccountState::Frozen));
    assert_eq!(view.metadata_pointer_address, Some(mint.pubkey()));
    assert_eq!(view.close_authority, Some(issuer.close_authority.pubkey()));
    assert_eq!(
        view.freeze_authority,
        Some(issuer.freeze_authority.pubkey())
    );
    assert_eq!(view.token_metadata.as_ref().unwrap().symbol, "RMTD");

    // New: seizure authority and confidentiality with MANUAL approval.
    assert_eq!(
        view.permanent_delegate,
        Some(issuer.permanent_delegate.pubkey())
    );
    let confidential = view
        .confidential_transfer
        .expect("confidential transfer config");
    assert!(
        !confidential.auto_approve_new_accounts,
        "approve_policy = manual means auto_approve_new_accounts = false"
    );
    assert_eq!(
        confidential.authority,
        Some(issuer.confidential_authority.pubkey())
    );
    assert_eq!(
        confidential.auditor_elgamal_pubkey,
        Some((*keys.auditor.pubkey()).into())
    );

    // Sized by the calculator, including the three new extensions.
    let layout = mint::mint_layout(
        &mint.pubkey(),
        &mint::v2_extensions(),
        &issuer.mint_params().metadata,
    )
    .unwrap();
    assert_eq!(
        env.svm.get_account(&mint.pubkey()).unwrap().data.len(),
        layout.funded_len
    );
}

#[test]
fn confidential_transfers_cannot_be_bolted_onto_the_existing_mint() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let v1 = env.create_v1_mint(&issuer);

    // Try to add ConfidentialTransferMint to the live v1 mint.
    let ix = ct_ix::initialize_mint(
        &token_program_id(),
        &v1.pubkey(),
        Some(issuer.confidential_authority.pubkey()),
        false,
        None,
    )
    .unwrap();
    let failed = env.send_err(&[ix], &[]);
    assert_token_error(&failed, TokenError::AlreadyInUse);

    // And the permanent delegate cannot be added after the fact either.
    let ix = spl_token_2022_interface::instruction::initialize_permanent_delegate(
        &token_program_id(),
        &v1.pubkey(),
        &issuer.permanent_delegate.pubkey(),
    )
    .unwrap();
    let failed = env.send_err(&[ix], &[]);
    assert_token_error(&failed, TokenError::AlreadyInUse);

    let view = state::fetch_mint(&env, &v1.pubkey()).unwrap();
    assert!(view.permanent_delegate.is_none() && view.confidential_transfer.is_none());
}

/// The re-issue itself: holders burn v1 against fresh v2 supply, then the old
/// mint is closed through its close authority.
#[test]
fn holders_migrate_by_burning_v1_and_the_old_mint_is_closed() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let keys = ConfidentialAuthorities::new();
    let v1 = env.create_v1_mint(&issuer);
    let alice = env.wallet();
    let v1_ata = env.onboard(&issuer, &v1.pubkey(), &alice.pubkey(), 100 * ONE);

    let v2 = env.create_v2_mint(&issuer, &keys);
    // The new account starts frozen again: KYC does not carry across mints.
    let v2_ata = env.create_ata_for(&alice.pubkey(), &v2.pubkey());
    assert_eq!(
        state::fetch_account(&env, &v2_ata).unwrap().state,
        AccountState::Frozen
    );
    assert_ne!(v1_ata, v2_ata);
    assert_eq!(v2_ata, ata_address(&alice.pubkey(), &v2.pubkey()));
    env.thaw(&issuer, &v2_ata, &v2.pubkey());

    let burn = burn_checked(
        &token_program_id(),
        &v1_ata,
        &v1.pubkey(),
        &alice.pubkey(),
        &[],
        100 * ONE,
        DECIMALS,
    )
    .unwrap();
    env.send_ok(&[burn], &[&alice]);
    env.mint_to(&issuer, &v2.pubkey(), &v2_ata, 100 * ONE);
    assert_eq!(env.supply(&v1.pubkey()), 0);
    assert_eq!(env.balance(&v2_ata), 100 * ONE);

    let close = close_account(
        &token_program_id(),
        &v1.pubkey(),
        &env.payer.pubkey(),
        &issuer.close_authority.pubkey(),
        &[],
    )
    .unwrap();
    env.send_ok(&[close], &[&issuer.close_authority]);
    assert!(env.svm.get_account(&v1.pubkey()).is_none());
}

// -- seizure (public balance) -----------------------------------------------

struct Seizure {
    env: Env,
    issuer: Issuer,
    mint: solana_keypair::Keypair,
    sanctioned: solana_keypair::Keypair,
    sanctioned_ata: remittance_stablecoin::Pubkey,
    treasury_ata: remittance_stablecoin::Pubkey,
}

fn seizure_fixture() -> Seizure {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let keys = ConfidentialAuthorities::new();
    let mint = env.create_v2_mint(&issuer, &keys);
    let sanctioned = env.wallet();
    let treasury = env.wallet();
    let sanctioned_ata = env.onboard(&issuer, &mint.pubkey(), &sanctioned.pubkey(), 1_000 * ONE);
    let treasury_ata = env.onboard(&issuer, &mint.pubkey(), &treasury.pubkey(), 0);
    Seizure {
        env,
        issuer,
        mint,
        sanctioned,
        sanctioned_ata,
        treasury_ata,
    }
}

#[test]
fn permanent_delegate_seizes_the_public_balance_without_the_owners_signature() {
    let mut f = seizure_fixture();
    let delegate = f.issuer.permanent_delegate.pubkey();

    let ix = seizure::seize_public_balance(&f.env, &f.sanctioned_ata, &f.treasury_ata, &delegate)
        .unwrap();
    // Only the permanent delegate signs. The owner is not involved at all.
    f.env.send_ok(&[ix], &[&f.issuer.permanent_delegate]);

    assert_eq!(f.env.balance(&f.sanctioned_ata), 0);
    // Seizure is still a transfer: the 2.5 token cap applies to the 1000 moved.
    assert_eq!(f.env.balance(&f.treasury_ata), 1_000 * ONE - MAX_FEE);
    assert_eq!(
        state::fetch_account(&f.env, &f.treasury_ata)
            .unwrap()
            .withheld_fee,
        Some(MAX_FEE)
    );
}

#[test]
fn permanent_delegate_can_also_burn() {
    let mut f = seizure_fixture();
    let delegate = f.issuer.permanent_delegate.pubkey();
    let ix = seizure::burn_public_balance(&f.env, &f.sanctioned_ata, &delegate).unwrap();
    f.env.send_ok(&[ix], &[&f.issuer.permanent_delegate]);
    assert_eq!(f.env.balance(&f.sanctioned_ata), 0);
    assert_eq!(f.env.supply(&f.mint.pubkey()), 0, "burned, so supply fell");
}

#[test]
fn only_the_permanent_delegate_can_seize() {
    let mut f = seizure_fixture();

    // Library guard.
    let err = seizure::seize_public_balance(
        &f.env,
        &f.sanctioned_ata,
        &f.treasury_ata,
        &f.issuer.freeze_authority.pubkey(),
    )
    .unwrap_err();
    assert!(matches!(err, Error::WrongAuthority { .. }), "{err}");

    // On-chain: build the same instruction signed by the freeze authority and
    // by the mint authority; both are refused.
    for impostor in [
        &f.issuer.freeze_authority,
        &f.issuer.mint_authority,
        &f.issuer.confidential_authority,
    ] {
        let ix = transfer::transfer_with_fee(
            &f.env,
            &f.sanctioned_ata,
            &f.treasury_ata,
            &impostor.pubkey(),
            10 * ONE,
        )
        .unwrap();
        let failed = f.env.send_err(&[ix], &[impostor]);
        assert_token_error(&failed, TokenError::OwnerMismatch);
    }
    assert_eq!(f.env.balance(&f.sanctioned_ata), 1_000 * ONE);
}

/// A frozen account cannot be seized: the frozen check comes before the
/// authority check. Seizing from a frozen account therefore needs the freeze
/// authority to thaw it first.
#[test]
fn a_frozen_account_cannot_be_seized_until_it_is_thawed() {
    let mut f = seizure_fixture();
    let delegate = f.issuer.permanent_delegate.pubkey();

    // Sanctions hit: freeze.
    let freeze = remittance_stablecoin::kyc::freeze(
        &f.env,
        &f.sanctioned_ata,
        &f.issuer.freeze_authority.pubkey(),
    )
    .unwrap();
    f.env.send_ok(&[freeze], &[&f.issuer.freeze_authority]);

    let ix = seizure::seize_public_balance(&f.env, &f.sanctioned_ata, &f.treasury_ata, &delegate)
        .unwrap();
    let failed = f
        .env
        .send_err(std::slice::from_ref(&ix), &[&f.issuer.permanent_delegate]);
    assert_token_error(&failed, TokenError::AccountFrozen);

    // Thaw, seize, and the funds move.
    f.env.thaw(&f.issuer, &f.sanctioned_ata, &f.mint.pubkey());
    f.env.send_ok(&[ix], &[&f.issuer.permanent_delegate]);
    assert_eq!(f.env.balance(&f.sanctioned_ata), 0);
    let _ = &f.sanctioned;
}
