//! Task 2: transfers use `transfer_checked_with_fee`, and the expected fee comes
//! from `calculate_epoch_fee(current_epoch, amount)`, never from a cached rate.

mod common;

use {
    common::*,
    remittance_stablecoin::{
        ChainReader, state, token_program_id,
        transfer::{self, quote_fee},
    },
    solana_signer::Signer,
    spl_token_2022_interface::{
        error::TokenError,
        extension::transfer_fee::instruction::{set_transfer_fee, transfer_checked_with_fee},
        instruction::{TokenInstruction, transfer_checked},
    },
};

struct Fixture {
    env: Env,
    issuer: Issuer,
    mint: solana_keypair::Keypair,
    alice: solana_keypair::Keypair,
    alice_ata: remittance_stablecoin::Pubkey,
    bob_ata: remittance_stablecoin::Pubkey,
}

fn fixture() -> Fixture {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let alice = env.wallet();
    let bob = env.wallet();
    let alice_ata = env.onboard(&issuer, &mint.pubkey(), &alice.pubkey(), 1_000 * ONE);
    let bob_ata = env.onboard(&issuer, &mint.pubkey(), &bob.pubkey(), 0);
    Fixture {
        env,
        issuer,
        mint,
        alice,
        alice_ata,
        bob_ata,
    }
}

#[test]
fn transfer_is_a_transfer_checked_with_fee_and_withholds_the_fee() {
    let mut f = fixture();
    let ix = transfer::transfer_with_fee(
        &f.env,
        &f.alice_ata,
        &f.bob_ata,
        &f.alice.pubkey(),
        200 * ONE,
    )
    .unwrap();

    // It really is the fee-extension instruction, not Transfer / TransferChecked.
    assert_eq!(
        TokenInstruction::unpack(&ix.data).unwrap(),
        TokenInstruction::TransferFeeExtension
    );
    assert_ne!(ix.data[0], 3, "not Transfer");
    assert_ne!(ix.data[0], 12, "not TransferChecked");

    f.env.send_ok(&[ix], &[&f.alice]);

    // 1% of 200 = 2. Bob gets 198, the 2 sits withheld in Bob's account.
    assert_eq!(f.env.balance(&f.alice_ata), 800 * ONE);
    assert_eq!(f.env.balance(&f.bob_ata), 198 * ONE);
    assert_eq!(
        state::fetch_account(&f.env, &f.bob_ata)
            .unwrap()
            .withheld_fee,
        Some(2 * ONE)
    );
    // Fees are not burned: supply is unchanged.
    assert_eq!(f.env.supply(&f.mint.pubkey()), 1_000 * ONE);
}

#[test]
fn fee_is_capped_at_the_maximum() {
    let mut f = fixture();
    // 1% of 1000 would be 10 tokens; the cap is 2.5.
    let ix = transfer::transfer_with_fee(
        &f.env,
        &f.alice_ata,
        &f.bob_ata,
        &f.alice.pubkey(),
        1_000 * ONE,
    )
    .unwrap();
    f.env.send_ok(&[ix], &[&f.alice]);
    assert_eq!(f.env.balance(&f.bob_ata), 1_000 * ONE - MAX_FEE);
    assert_eq!(
        state::fetch_account(&f.env, &f.bob_ata)
            .unwrap()
            .withheld_fee,
        Some(MAX_FEE)
    );
}

#[test]
fn quote_matches_calculate_epoch_fee_for_the_current_epoch() {
    let f = fixture();
    let data = f.env.svm.get_account(&f.mint.pubkey()).unwrap().data;

    let small = quote_fee(&data, 0, 50 * ONE).unwrap();
    assert_eq!((small.fee, small.net_amount()), (500_000, 49_500_000));
    assert_eq!(small.basis_points, FEE_BPS);
    assert_eq!(small.decimals, DECIMALS);

    // Rounds up, so a dust transfer still pays at least 1 base unit...
    assert_eq!(quote_fee(&data, 0, 1).unwrap().fee, 1);
    // ...and a zero transfer pays nothing.
    assert_eq!(quote_fee(&data, 0, 0).unwrap().fee, 0);
    // The cap binds.
    assert_eq!(quote_fee(&data, 0, 10_000 * ONE).unwrap().fee, MAX_FEE);
}

/// Plain `TransferChecked` is *not* refused on a fee mint: the program computes
/// the fee itself and applies it. That is exactly the problem: the sender has
/// no say. If the schedule changes between quoting and landing, a plain
/// transfer silently pays the new rate, whereas `TransferCheckedWithFee`
/// (previous test) refuses with `FeeMismatch`.
#[test]
fn plain_transfer_checked_silently_pays_whatever_fee_is_current() {
    let mut f = fixture();
    let plain = |f: &Fixture| {
        transfer_checked(
            &token_program_id(),
            &f.alice_ata,
            &f.mint.pubkey(),
            &f.bob_ata,
            &f.alice.pubkey(),
            &[],
            100 * ONE,
            DECIMALS,
        )
        .unwrap()
    };

    // Works, and the program charges the fee on the sender's behalf.
    let ix = plain(&f);
    f.env.send_ok(&[ix], &[&f.alice]);
    assert_eq!(f.env.balance(&f.bob_ata), 99 * ONE); // 1% fee

    // The issuer schedules 5%; the epoch rolls over.
    let set = set_transfer_fee(
        &token_program_id(),
        &f.mint.pubkey(),
        &f.issuer.fee_config_authority.pubkey(),
        &[],
        500,
        10 * ONE,
    )
    .unwrap();
    f.env.send_ok(&[set], &[&f.issuer.fee_config_authority]);
    let activation = state::fetch_mint(&f.env, &f.mint.pubkey())
        .unwrap()
        .transfer_fee
        .unwrap()
        .newer
        .epoch;
    f.env.set_epoch(activation);

    // Same bytes as before. No error, no warning: the sender just pays 5%.
    let ix = plain(&f);
    f.env.send_ok(&[ix], &[&f.alice]);
    assert_eq!(f.env.balance(&f.bob_ata), 99 * ONE + 95 * ONE);
}

#[test]
fn the_program_rejects_a_fee_that_does_not_match_its_own_calculation() {
    let mut f = fixture();
    let correct = 2 * ONE; // 1% of 200
    for wrong_fee in [0, correct - 1, correct + 1] {
        let ix = transfer_checked_with_fee(
            &token_program_id(),
            &f.alice_ata,
            &f.mint.pubkey(),
            &f.bob_ata,
            &f.alice.pubkey(),
            &[],
            200 * ONE,
            DECIMALS,
            wrong_fee,
        )
        .unwrap();
        let failed = f.env.send_err(&[ix], &[&f.alice]);
        assert_token_error(&failed, TokenError::FeeMismatch);
    }
    assert_eq!(f.env.balance(&f.alice_ata), 1_000 * ONE);
}

/// The schedule keeps an `older` and a `newer` entry; a change only takes
/// effect from the `newer` entry's epoch. A rate cached before the change is
/// wrong from that epoch on, and the program says so.
#[test]
fn fee_follows_the_epoch_schedule_and_a_cached_rate_goes_stale() {
    let mut f = fixture();

    // Price a transfer today and keep the number, the way a cached rate would.
    let cached_quote = quote_fee(
        &f.env.svm.get_account(&f.mint.pubkey()).unwrap().data,
        f.env.current_epoch(),
        100 * ONE,
    )
    .unwrap();
    assert_eq!(cached_quote.fee, ONE); // 1% of 100

    // Schedule 3% for a later epoch.
    let set = set_transfer_fee(
        &token_program_id(),
        &f.mint.pubkey(),
        &f.issuer.fee_config_authority.pubkey(),
        &[],
        300,
        10 * ONE,
    )
    .unwrap();
    f.env.send_ok(&[set], &[&f.issuer.fee_config_authority]);

    let schedule = state::fetch_mint(&f.env, &f.mint.pubkey())
        .unwrap()
        .transfer_fee
        .unwrap();
    let activation_epoch = schedule.newer.epoch;
    assert!(
        activation_epoch > f.env.current_epoch(),
        "change is scheduled, not immediate"
    );
    assert_eq!(schedule.older.basis_points, FEE_BPS);
    assert_eq!(schedule.newer.basis_points, 300);

    // Before the activation epoch the old rate still applies, so the cached fee is still right.
    let still_old = transfer::transfer_with_fee(
        &f.env,
        &f.alice_ata,
        &f.bob_ata,
        &f.alice.pubkey(),
        100 * ONE,
    )
    .unwrap();
    f.env.send_ok(&[still_old], &[&f.alice]);
    assert_eq!(f.env.balance(&f.bob_ata), 99 * ONE);

    // Cross into the activation epoch.
    f.env.set_epoch(activation_epoch);
    assert_eq!(f.env.current_epoch(), activation_epoch);

    // The cached 1% fee is now rejected on chain...
    let stale = transfer_checked_with_fee(
        &token_program_id(),
        &f.alice_ata,
        &f.mint.pubkey(),
        &f.bob_ata,
        &f.alice.pubkey(),
        &[],
        100 * ONE,
        DECIMALS,
        cached_quote.fee,
    )
    .unwrap();
    let failed = f.env.send_err(&[stale], &[&f.alice]);
    assert_token_error(&failed, TokenError::FeeMismatch);

    // ...while the freshly computed fee (3%) goes through.
    let fresh = transfer::transfer_with_fee(
        &f.env,
        &f.alice_ata,
        &f.bob_ata,
        &f.alice.pubkey(),
        100 * ONE,
    )
    .unwrap();
    f.env.send_ok(&[fresh], &[&f.alice]);
    assert_eq!(f.env.balance(&f.bob_ata), 99 * ONE + 97 * ONE);
}

#[test]
fn only_the_fee_config_authority_can_reschedule_the_fee() {
    let mut f = fixture();
    let intruder = f.env.wallet();
    let ix = set_transfer_fee(
        &token_program_id(),
        &f.mint.pubkey(),
        &intruder.pubkey(),
        &[],
        0,
        0,
    )
    .unwrap();
    let failed = f.env.send_err(&[ix], &[&intruder]);
    assert_token_error(&failed, TokenError::OwnerMismatch);
}
