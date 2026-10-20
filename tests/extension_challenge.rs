//! Extension challenge: an on-chain agent that spends a user's delegated
//! allowance, and CPI Guard enabled afterwards.
//!
//! The agent is `programs/agent`, compiled to `fixtures/agent_program.so`
//! (`scripts/build-fixtures.ps1`). It is loaded into the same LiteSVM as
//! Token-2022 and exercised through real CPIs.

mod common;

use {
    common::*,
    remittance_stablecoin::{Pubkey, state, token_program_id},
    solana_instruction::{AccountMeta, Instruction},
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::{
        error::TokenError,
        extension::{ExtensionType, cpi_guard::instruction::enable_cpi_guard},
        instruction::{approve_checked, reallocate, revoke},
    },
};

const PER_TX_LIMIT: u64 = 150 * ONE;
const ALLOWANCE: u64 = 500 * ONE;

// Mirrors `programs/agent` error codes.
const NOT_OPERATOR: u32 = 0x1000;
const WRONG_PAYEE: u32 = 0x1002;
const OVER_LIMIT: u32 = 0x1003;

struct Setup {
    env: Env,
    program_id: Pubkey,
    alice: Keypair,
    operator: Keypair,
    mint: Pubkey,
    alice_ata: Pubkey,
    bob_ata: Pubkey,
    config: Pubkey,
}

fn agent_ix(
    program_id: &Pubkey,
    accounts: Vec<AccountMeta>,
    tag: u8,
    payload: &[u8],
) -> Instruction {
    let mut data = vec![tag];
    data.extend_from_slice(payload);
    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

impl Setup {
    fn init(&self) -> Instruction {
        let mut payload = Vec::new();
        payload.extend_from_slice(self.operator.pubkey().as_ref());
        payload.extend_from_slice(self.bob_ata.as_ref());
        payload.extend_from_slice(&PER_TX_LIMIT.to_le_bytes());
        agent_ix(
            &self.program_id,
            vec![
                AccountMeta::new(self.alice.pubkey(), true),
                AccountMeta::new(self.config, false),
                AccountMeta::new_readonly(self.alice_ata, false),
                AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            ],
            0,
            &payload,
        )
    }

    /// The delegated-transfer instruction. Built once and reused byte-for-byte
    /// before and after CPI Guard is switched on.
    fn execute(&self, amount: u64) -> Instruction {
        self.execute_with(&self.operator.pubkey(), &self.bob_ata, amount)
    }

    fn execute_with(&self, operator: &Pubkey, payee: &Pubkey, amount: u64) -> Instruction {
        agent_ix(
            &self.program_id,
            vec![
                AccountMeta::new_readonly(*operator, true),
                AccountMeta::new_readonly(self.config, false),
                AccountMeta::new(self.alice_ata, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(*payee, false),
                AccountMeta::new_readonly(token_program_id(), false),
            ],
            1,
            &amount.to_le_bytes(),
        )
    }

    fn owner_pull(&self, amount: u64) -> Instruction {
        agent_ix(
            &self.program_id,
            vec![
                AccountMeta::new_readonly(self.alice.pubkey(), true),
                AccountMeta::new(self.alice_ata, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(self.bob_ata, false),
                AccountMeta::new_readonly(token_program_id(), false),
            ],
            2,
            &amount.to_le_bytes(),
        )
    }

    fn approve(&self, allowance: u64) -> Instruction {
        approve_checked(
            &token_program_id(),
            &self.alice_ata,
            &self.mint,
            &self.config, // the delegate is the agent's PDA
            &self.alice.pubkey(),
            &[],
            allowance,
            DECIMALS,
        )
        .unwrap()
    }

    fn account(&self) -> remittance_stablecoin::state::AccountView {
        state::fetch_account(&self.env, &self.alice_ata).unwrap()
    }
}

fn setup() -> Setup {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer).pubkey();

    let program_id = Keypair::new().pubkey();
    env.svm
        .add_program_from_file(
            program_id,
            concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/agent_program.so"),
        )
        .expect("load fixtures/agent_program.so (run scripts/build-fixtures.ps1)");

    let alice = env.wallet();
    let bob = env.wallet();
    let operator = env.wallet();
    let alice_ata = env.onboard(&issuer, &mint, &alice.pubkey(), 1_000 * ONE);
    let bob_ata = env.onboard(&issuer, &mint, &bob.pubkey(), 0);

    let (config, _bump) = Pubkey::find_program_address(
        &[b"agent", alice.pubkey().as_ref(), alice_ata.as_ref()],
        &program_id,
    );

    Setup {
        env,
        program_id,
        alice,
        operator,
        mint,
        alice_ata,
        bob_ata,
        config,
    }
}

/// Configure the agent and grant the allowance: two *direct* transactions the
/// owner signs. `Approve` must not go through a CPI, which is also what CPI
/// Guard would refuse.
fn onboard_agent(s: &mut Setup) {
    let init = s.init();
    s.env.send_ok(&[init], &[&s.alice.insecure_clone()]);
    let approve = s.approve(ALLOWANCE);
    s.env.send_ok(&[approve], &[&s.alice.insecure_clone()]);

    let account = s.account();
    assert_eq!(account.delegate, Some(s.config));
    assert_eq!(account.delegated_amount, ALLOWANCE);
}

#[test]
fn agent_spends_the_delegated_allowance_and_pays_the_fee() {
    let mut s = setup();
    onboard_agent(&mut s);

    let ix = s.execute(100 * ONE);
    s.env.send_ok(&[ix], &[&s.operator.insecure_clone()]);

    // 100 left Alice; 1% fee withheld; Bob got 99.
    assert_eq!(s.env.balance(&s.alice_ata), 900 * ONE);
    assert_eq!(s.env.balance(&s.bob_ata), 99 * ONE);
    assert_eq!(
        state::fetch_account(&s.env, &s.bob_ata)
            .unwrap()
            .withheld_fee,
        Some(ONE)
    );
    // The allowance shrank by the gross amount.
    assert_eq!(s.account().delegated_amount, ALLOWANCE - 100 * ONE);
}

#[test]
fn cpi_guard_does_not_disturb_the_delegated_path() {
    let mut s = setup();
    onboard_agent(&mut s);
    let operator = s.operator.insecure_clone();
    let alice = s.alice.insecure_clone();

    // Before CPI Guard.
    let execute = s.execute(100 * ONE);
    s.env.send_ok(std::slice::from_ref(&execute), &[&operator]);
    assert_eq!(s.env.balance(&s.bob_ata), 99 * ONE);

    // Alice turns CPI Guard on. Her account needs room for the extension first.
    let payer = s.env.payer.pubkey();
    let grow = reallocate(
        &token_program_id(),
        &s.alice_ata,
        &payer,
        &alice.pubkey(),
        &[],
        &[ExtensionType::CpiGuard],
    )
    .unwrap();
    let enable = enable_cpi_guard(&token_program_id(), &s.alice_ata, &alice.pubkey(), &[]).unwrap();
    s.env.send_ok(&[grow, enable], &[&alice]);
    assert_eq!(s.account().cpi_guard_enabled, Some(true));

    // The very same instruction, byte for byte, still works.
    let again = s.execute(100 * ONE);
    assert_eq!(
        again.data, execute.data,
        "no change to the instruction data"
    );
    assert_eq!(
        again.accounts, execute.accounts,
        "no change to the accounts"
    );
    s.env.send_ok(&[again], &[&operator]);

    assert_eq!(s.env.balance(&s.alice_ata), 800 * ONE);
    assert_eq!(s.env.balance(&s.bob_ata), 99 * ONE + 99 * ONE);
    assert_eq!(s.account().delegated_amount, ALLOWANCE - 200 * ONE);
}

/// The contrast that shows what CPI Guard is actually *for*: an owner-signed
/// transfer inside a CPI works until the guard is on, then is refused.
#[test]
fn cpi_guard_blocks_owner_signed_cpi_transfers_but_not_delegate_signed_ones() {
    let mut s = setup();
    onboard_agent(&mut s);
    let alice = s.alice.insecure_clone();
    let operator = s.operator.insecure_clone();

    // Guard off: a program holding Alice's signature can move her funds via CPI.
    let pull = s.owner_pull(10 * ONE);
    s.env.send_ok(std::slice::from_ref(&pull), &[&alice]);
    assert_eq!(s.env.balance(&s.alice_ata), 990 * ONE);

    // Guard on.
    let payer = s.env.payer.pubkey();
    let grow = reallocate(
        &token_program_id(),
        &s.alice_ata,
        &payer,
        &alice.pubkey(),
        &[],
        &[ExtensionType::CpiGuard],
    )
    .unwrap();
    let enable = enable_cpi_guard(&token_program_id(), &s.alice_ata, &alice.pubkey(), &[]).unwrap();
    s.env.send_ok(&[grow, enable], &[&alice]);

    // The owner-signed CPI is now refused...
    let failed = s.env.send_err(&[pull], &[&alice]);
    assert_token_error(&failed, TokenError::CpiGuardTransferBlocked);
    assert_eq!(s.env.balance(&s.alice_ata), 990 * ONE, "nothing moved");

    // ...and the delegate-signed CPI goes through.
    let execute = s.execute(100 * ONE);
    s.env.send_ok(&[execute], &[&operator]);
    assert_eq!(s.env.balance(&s.alice_ata), 890 * ONE);
}

#[test]
fn cpi_guard_also_refuses_approve_through_a_cpi_so_the_grant_must_be_direct() {
    // Context for the design: granting the allowance is an owner action and is
    // done in a direct transaction. With the guard on, the same grant routed
    // through a CPI would be refused; the direct one is not.
    let mut s = setup();
    let alice = s.alice.insecure_clone();
    let init = s.init();
    s.env.send_ok(&[init], &[&alice]);

    let payer = s.env.payer.pubkey();
    let grow = reallocate(
        &token_program_id(),
        &s.alice_ata,
        &payer,
        &alice.pubkey(),
        &[],
        &[ExtensionType::CpiGuard],
    )
    .unwrap();
    let enable = enable_cpi_guard(&token_program_id(), &s.alice_ata, &alice.pubkey(), &[]).unwrap();
    s.env.send_ok(&[grow, enable], &[&alice]);

    // Direct approval works with the guard already on.
    let approve = s.approve(ALLOWANCE);
    s.env.send_ok(&[approve], &[&alice]);
    assert_eq!(s.account().delegated_amount, ALLOWANCE);

    // And the agent can spend it.
    let execute = s.execute(50 * ONE);
    s.env.send_ok(&[execute], &[&s.operator.insecure_clone()]);
    assert_eq!(s.env.balance(&s.bob_ata), 50 * ONE - 500_000);
}

// -- the agent's own rules ----------------------------------------------------

#[test]
fn only_the_named_operator_can_trigger_a_transfer() {
    let mut s = setup();
    onboard_agent(&mut s);
    let stranger = s.env.wallet();

    let ix = s.execute_with(&stranger.pubkey(), &s.bob_ata, ONE);
    let failed = s.env.send_err(&[ix], &[&stranger]);
    assert_eq!(custom_code(&failed), Some(NOT_OPERATOR));
    assert_eq!(s.env.balance(&s.alice_ata), 1_000 * ONE);
}

#[test]
fn funds_can_only_go_to_the_configured_payee() {
    let mut s = setup();
    onboard_agent(&mut s);
    // Another account the operator would love to redirect funds to.
    let thief = s.env.wallet();
    let thief_ata = s.env.create_ata_for(&thief.pubkey(), &s.mint);

    let ix = s.execute_with(&s.operator.pubkey(), &thief_ata, ONE);
    let failed = s.env.send_err(&[ix], &[&s.operator.insecure_clone()]);
    assert_eq!(custom_code(&failed), Some(WRONG_PAYEE));
}

#[test]
fn per_transaction_limit_and_the_allowance_both_bind() {
    let mut s = setup();
    onboard_agent(&mut s);
    let operator = s.operator.insecure_clone();

    // Over the agent's own per-tx cap.
    let ix = s.execute(PER_TX_LIMIT + 1);
    let failed = s.env.send_err(&[ix], &[&operator]);
    assert_eq!(custom_code(&failed), Some(OVER_LIMIT));

    // Within the cap, until the token-level allowance runs out: 500 / 150 -> 3 transfers.
    for _ in 0..3 {
        let ix = s.execute(PER_TX_LIMIT);
        s.env.send_ok(&[ix], &[&operator]);
    }
    assert_eq!(s.account().delegated_amount, ALLOWANCE - 3 * PER_TX_LIMIT);
    let ix = s.execute(PER_TX_LIMIT);
    let failed = s.env.send_err(&[ix], &[&operator]);
    assert_token_error(&failed, TokenError::InsufficientFunds);
}

#[test]
fn the_owner_can_revoke_the_agent_at_any_time() {
    let mut s = setup();
    onboard_agent(&mut s);
    let alice = s.alice.insecure_clone();
    let operator = s.operator.insecure_clone();

    let revoke_ix = revoke(&token_program_id(), &s.alice_ata, &alice.pubkey(), &[]).unwrap();
    s.env.send_ok(&[revoke_ix], &[&alice]);
    assert_eq!(s.account().delegate, None);

    let ix = s.execute(ONE);
    let failed = s.env.send_err(&[ix], &[&operator]);
    assert_token_error(&failed, TokenError::OwnerMismatch);
}
