//! Task 6: the full confidential lifecycle, end to end, with real
//! zero-knowledge proofs verified by the ZK ElGamal Proof program.
//!
//! ConfigureAccount (owner-only) -> ApproveAccount (manual policy) -> thaw (KYC)
//! -> DepositConfidentialTokens -> ApplyPendingBalance -> confidential Transfer
//! -> ApplyPendingBalance (receiver) -> WithdrawConfidentialTokens.

mod common;

use {
    common::*,
    remittance_stablecoin::{
        Pubkey,
        confidential::{self, ConfidentialKeys},
        state,
    },
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::{error::TokenError, extension::ExtensionType},
};

struct World {
    env: Env,
    issuer: Issuer,
    authorities: ConfidentialAuthorities,
    mint: Keypair,
    alice: Keypair,
    bob: Keypair,
    alice_ata: Pubkey,
    bob_ata: Pubkey,
    alice_keys: ConfidentialKeys,
    bob_keys: ConfidentialKeys,
}

/// Accounts exist (created by the fee payer, not the owners) but nothing is
/// configured, approved or thawed yet.
fn world() -> World {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let authorities = ConfidentialAuthorities::new();
    let mint = env.create_v2_mint(&issuer, &authorities);
    let alice = env.wallet();
    let bob = env.wallet();
    // Permissionless: the payer creates both owners' accounts.
    let alice_ata = env.create_ata_for(&alice.pubkey(), &mint.pubkey());
    let bob_ata = env.create_ata_for(&bob.pubkey(), &mint.pubkey());
    let alice_keys = ConfidentialKeys::derive(&alice).unwrap();
    let bob_keys = ConfidentialKeys::derive(&bob).unwrap();
    World {
        env,
        issuer,
        authorities,
        mint,
        alice,
        bob,
        alice_ata,
        bob_ata,
        alice_keys,
        bob_keys,
    }
}

impl World {
    fn configure(&mut self, who: Who) {
        let (owner, ata, keys) = self.parts(who);
        let payer = self.env.payer.pubkey();
        let ixs = confidential::configure_account(&self.env, &payer, &owner.pubkey(), &ata, keys)
            .unwrap();
        let owner = self.owner(who);
        // `owner` borrows self; clone the keypair bytes to release the borrow.
        let owner = Keypair::try_from(owner.to_bytes().as_slice()).unwrap();
        self.env.send_ok(&ixs, &[&owner]);
    }

    fn approve(&mut self, ata: &Pubkey) {
        let ix = confidential::approve_account(
            ata,
            &self.mint.pubkey(),
            &self.issuer.confidential_authority.pubkey(),
        )
        .unwrap();
        self.env
            .send_ok(&[ix], &[&self.issuer.confidential_authority]);
    }

    fn thaw(&mut self, ata: &Pubkey) {
        let mint = self.mint.pubkey();
        self.env.thaw(&self.issuer, ata, &mint);
    }

    fn deposit(&mut self, who: Who, amount: u64) {
        let (_, ata, _) = self.parts(who);
        let owner = self.owner_clone(who);
        let ix = confidential::deposit(&self.env, &ata, &owner.pubkey(), amount).unwrap();
        self.env.send_ok(&[ix], &[&owner]);
    }

    fn apply_pending(&mut self, who: Who) {
        let (_, ata, keys) = self.parts(who);
        let owner = self.owner_clone(who);
        let ix =
            confidential::apply_pending_balance(&self.env, &ata, &owner.pubkey(), keys).unwrap();
        self.env.send_ok(&[ix], &[&owner]);
    }

    fn state_of(&self, who: Who) -> remittance_stablecoin::confidential::ConfidentialStateView {
        let (_, ata, keys) = self.parts(who);
        confidential::view(&self.env, &ata, keys).unwrap()
    }

    fn parts(&self, who: Who) -> (&Keypair, Pubkey, &ConfidentialKeys) {
        match who {
            Who::Alice => (&self.alice, self.alice_ata, &self.alice_keys),
            Who::Bob => (&self.bob, self.bob_ata, &self.bob_keys),
        }
    }

    fn owner(&self, who: Who) -> &Keypair {
        self.parts(who).0
    }

    fn owner_clone(&self, who: Who) -> Keypair {
        Keypair::try_from(self.owner(who).to_bytes().as_slice()).unwrap()
    }
}

#[derive(Clone, Copy)]
enum Who {
    Alice,
    Bob,
}

#[test]
fn full_confidential_lifecycle() {
    let mut w = world();
    let mint = w.mint.pubkey();

    // ---- Creation by a third party opts nobody in ---------------------------
    let created = state::fetch_account(&w.env, &w.alice_ata).unwrap();
    assert_eq!(
        created.owner,
        w.alice.pubkey(),
        "owner is Alice even though the payer created it"
    );
    assert!(created.confidential.is_none());
    assert!(
        !created
            .extensions
            .contains(&ExtensionType::ConfidentialTransferAccount)
    );

    // ---- ConfigureAccount: owner signs --------------------------------------
    w.configure(Who::Alice);
    w.configure(Who::Bob);
    for who in [Who::Alice, Who::Bob] {
        let account = state::fetch_account(&w.env, &w.parts(who).1).unwrap();
        assert!(
            account
                .extensions
                .contains(&ExtensionType::ConfidentialTransferAccount)
        );
        assert!(
            account
                .extensions
                .contains(&ExtensionType::ConfidentialTransferFeeAmount)
        );
        let ct = account.confidential.unwrap();
        assert!(
            !bool::from(ct.approved),
            "manual policy: configured is not approved"
        );
    }

    // ---- ApproveAccount (manual policy) + KYC thaw -------------------------
    let (alice_ata, bob_ata) = (w.alice_ata, w.bob_ata);
    w.approve(&alice_ata);
    w.approve(&bob_ata);
    w.thaw(&alice_ata);
    w.thaw(&bob_ata);
    assert!(bool::from(
        state::fetch_account(&w.env, &alice_ata)
            .unwrap()
            .confidential
            .unwrap()
            .approved
    ));

    // Alice funds her public balance: 100 tokens.
    w.env.mint_to(&w.issuer, &mint, &alice_ata, 100 * ONE);

    // ---- DepositConfidentialTokens -----------------------------------------
    w.deposit(Who::Alice, 100 * ONE);
    assert_eq!(
        w.env.balance(&alice_ata),
        0,
        "public balance moved into the confidential balance"
    );
    let alice = w.state_of(Who::Alice);
    assert_eq!(alice.pending, 100 * ONE);
    assert_eq!(
        alice.available, 0,
        "deposited funds are pending, not yet spendable"
    );
    assert_eq!(alice.pending_credit_counter, 1);

    // ---- ApplyPendingBalance -----------------------------------------------
    w.apply_pending(Who::Alice);
    let alice = w.state_of(Who::Alice);
    assert_eq!((alice.pending, alice.available), (0, 100 * ONE));
    assert_eq!(
        alice.available_by_elgamal,
        100 * ONE,
        "AES copy and ciphertext agree"
    );

    // ---- confidential Transfer: Alice -> Bob, 40 tokens ---------------------
    let payer = w.env.payer.pubkey();
    let transfer_amount = 40 * ONE;
    let plan = confidential::plan_transfer(
        &w.env,
        &payer,
        &w.alice.pubkey(),
        &alice_ata,
        &bob_ata,
        transfer_amount,
        &w.alice_keys,
        &|len| w.env.rent(len),
    )
    .unwrap();
    // 1% of 40 = 0.4
    assert_eq!(plan.fee, 400_000);
    let alice_signer = w.owner_clone(Who::Alice);
    let meta = w.env.run_plan(&plan.plan, &alice_signer);
    println!(
        "confidential transfer: {} setup transactions, main instruction used {} CU",
        plan.plan.setup.len(),
        meta.compute_units_consumed
    );

    let alice = w.state_of(Who::Alice);
    assert_eq!(
        alice.available,
        60 * ONE,
        "sender's balance dropped by the gross amount"
    );
    // Receiver sees the NET amount as pending.
    let bob = w.state_of(Who::Bob);
    assert_eq!(bob.pending, transfer_amount - 400_000);
    assert_eq!(bob.available, 0);
    // The public balances never moved: the transfer is invisible there.
    assert_eq!(w.env.balance(&alice_ata), 0);
    assert_eq!(w.env.balance(&bob_ata), 0);

    // The auditor, and only the auditor, can read the amount off the instruction.
    let audited = confidential::decrypt_auditor_amount(
        &w.authorities.auditor,
        plan.auditor_ciphertext_lo,
        plan.auditor_ciphertext_hi,
    )
    .unwrap();
    assert_eq!(audited, transfer_amount);

    // ---- Withdraw before applying pending: refused --------------------------
    let bob_pending_net = transfer_amount - 400_000;
    let early = confidential::plan_withdraw(
        &w.env,
        &payer,
        &w.bob.pubkey(),
        &bob_ata,
        bob_pending_net,
        &w.bob_keys,
        &|len| w.env.rent(len),
    );
    assert!(
        early.is_err(),
        "pending credits are not spendable: withdraw must wait for ApplyPendingBalance"
    );

    // ---- ApplyPendingBalance (receiver), then Withdraw ---------------------
    w.apply_pending(Who::Bob);
    let bob = w.state_of(Who::Bob);
    assert_eq!((bob.pending, bob.available), (0, bob_pending_net));

    let plan = confidential::plan_withdraw(
        &w.env,
        &payer,
        &w.bob.pubkey(),
        &bob_ata,
        bob_pending_net,
        &w.bob_keys,
        &|len| w.env.rent(len),
    )
    .unwrap();
    let bob_signer = w.owner_clone(Who::Bob);
    w.env.run_plan(&plan, &bob_signer);

    assert_eq!(
        w.env.balance(&bob_ata),
        bob_pending_net,
        "withdrawn amount is public again"
    );
    assert_eq!(w.state_of(Who::Bob).available, 0);

    // Alice withdraws what is left.
    let plan = confidential::plan_withdraw(
        &w.env,
        &payer,
        &w.alice.pubkey(),
        &alice_ata,
        60 * ONE,
        &w.alice_keys,
        &|len| w.env.rent(len),
    )
    .unwrap();
    w.env.run_plan(&plan, &alice_signer);
    assert_eq!(w.env.balance(&alice_ata), 60 * ONE);
    assert_eq!(w.state_of(Who::Alice).available, 0);

    // Conservation: nothing was created or destroyed. The only token not in a
    // public balance is the 0.4 fee, withheld (encrypted) inside Bob's account.
    assert_eq!(w.env.supply(&mint), 100 * ONE);
    assert_eq!(
        w.env.balance(&alice_ata) + w.env.balance(&bob_ata) + 400_000,
        100 * ONE
    );
}

#[test]
fn only_the_owner_can_configure_even_though_anyone_could_create_the_account() {
    let mut w = world();
    let attacker = w.env.wallet();
    let attacker_keys = ConfidentialKeys::derive(&attacker).unwrap();
    let payer = w.env.payer.pubkey();

    // The attacker names themselves as authority over Alice's account.
    let ixs = confidential::configure_account(
        &w.env,
        &payer,
        &attacker.pubkey(),
        &w.alice_ata,
        &attacker_keys,
    )
    .unwrap();
    let failed = w.env.send_err(&ixs, &[&attacker]);
    assert_token_error(&failed, TokenError::OwnerMismatch);

    // Neither the issuer's other keys nor the permanent delegate fare better.
    for impostor in [
        &w.issuer.permanent_delegate,
        &w.issuer.freeze_authority,
        &w.issuer.confidential_authority,
    ] {
        let keys = ConfidentialKeys::derive(impostor).unwrap();
        let ixs = confidential::configure_account(
            &w.env,
            &payer,
            &impostor.pubkey(),
            &w.alice_ata,
            &keys,
        )
        .unwrap();
        let failed = w.env.send_err(&ixs, &[impostor]);
        assert_token_error(&failed, TokenError::OwnerMismatch);
    }

    let account = state::fetch_account(&w.env, &w.alice_ata).unwrap();
    assert!(
        account.confidential.is_none(),
        "Alice's account is untouched"
    );

    // Alice, the owner, can.
    w.configure(Who::Alice);
    assert!(
        state::fetch_account(&w.env, &w.alice_ata)
            .unwrap()
            .confidential
            .is_some()
    );
}

#[test]
fn manual_policy_blocks_deposits_until_the_issuer_approves() {
    let mut w = world();
    let alice_ata = w.alice_ata;
    w.configure(Who::Alice);
    w.thaw(&alice_ata);
    w.env
        .mint_to(&w.issuer, &w.mint.pubkey(), &alice_ata, 10 * ONE);

    let owner = w.owner_clone(Who::Alice);
    let ix = confidential::deposit(&w.env, &alice_ata, &owner.pubkey(), 5 * ONE).unwrap();
    let failed = w.env.send_err(std::slice::from_ref(&ix), &[&owner]);
    assert_token_error(&failed, TokenError::ConfidentialTransferAccountNotApproved);
    assert_eq!(w.env.balance(&alice_ata), 10 * ONE, "nothing moved");

    // Only the confidential-transfer authority can approve.
    let impostor_ix = confidential::approve_account(
        &alice_ata,
        &w.mint.pubkey(),
        &w.issuer.freeze_authority.pubkey(),
    )
    .unwrap();
    assert!(
        w.env
            .send(&[impostor_ix], &[&w.issuer.freeze_authority])
            .is_err()
    );

    w.approve(&alice_ata);
    w.env.send_ok(&[ix], &[&owner]);
    assert_eq!(w.env.balance(&alice_ata), 5 * ONE);
}

#[test]
fn a_frozen_account_cannot_use_confidential_instructions() {
    let mut w = world();
    let alice_ata = w.alice_ata;
    w.configure(Who::Alice);
    w.approve(&alice_ata);
    w.thaw(&alice_ata);
    w.env
        .mint_to(&w.issuer, &w.mint.pubkey(), &alice_ata, 10 * ONE);
    w.deposit(Who::Alice, 4 * ONE);

    // Compliance freezes the account with a confidential balance in flight.
    let freeze =
        remittance_stablecoin::kyc::freeze(&w.env, &alice_ata, &w.issuer.freeze_authority.pubkey())
            .unwrap();
    w.env.send_ok(&[freeze], &[&w.issuer.freeze_authority]);

    let owner = w.owner_clone(Who::Alice);
    let ix = confidential::deposit(&w.env, &alice_ata, &owner.pubkey(), ONE).unwrap();
    assert_token_error(&w.env.send_err(&[ix], &[&owner]), TokenError::AccountFrozen);

    let ix =
        confidential::apply_pending_balance(&w.env, &alice_ata, &owner.pubkey(), &w.alice_keys)
            .unwrap();
    assert_token_error(&w.env.send_err(&[ix], &[&owner]), TokenError::AccountFrozen);
}

/// Why the transfer needs a Record account: the sizes of the five proofs that a
/// fee-bearing confidential transfer carries, against the packet limit.
#[test]
fn only_the_range_proofs_are_too_big_to_verify_from_instruction_data() {
    use {
        spl_token_2022_interface::solana_zk_elgamal_proof_interface::proof_data::{
            BatchedGroupedCiphertext2HandlesValidityProofData,
            BatchedGroupedCiphertext3HandlesValidityProofData, BatchedRangeProofU64Data,
            BatchedRangeProofU256Data, CiphertextCommitmentEqualityProofData,
            PercentageWithCapProofData, PubkeyValidityProofData,
        },
        std::mem::size_of,
    };

    let sizes = [
        (
            "PubkeyValidity (ConfigureAccount)",
            size_of::<PubkeyValidityProofData>(),
        ),
        (
            "CiphertextCommitmentEquality",
            size_of::<CiphertextCommitmentEqualityProofData>(),
        ),
        (
            "BatchedGroupedCiphertext3HandlesValidity",
            size_of::<BatchedGroupedCiphertext3HandlesValidityProofData>(),
        ),
        (
            "PercentageWithCap (fee sigma)",
            size_of::<PercentageWithCapProofData>(),
        ),
        (
            "BatchedGroupedCiphertext2HandlesValidity",
            size_of::<BatchedGroupedCiphertext2HandlesValidityProofData>(),
        ),
        (
            "BatchedRangeProofU64 (Withdraw)",
            size_of::<BatchedRangeProofU64Data>(),
        ),
        (
            "BatchedRangeProofU256 (Transfer)",
            size_of::<BatchedRangeProofU256Data>(),
        ),
    ];
    for (name, size) in sizes {
        println!("{size:>5} bytes  {name}");
    }

    // A verify transaction also carries signatures, account keys, a blockhash
    // and the compute-budget instruction: roughly 330 bytes of overhead.
    let room = 1232 - 330;
    assert!(size_of::<CiphertextCommitmentEqualityProofData>() < room);
    assert!(size_of::<BatchedGroupedCiphertext3HandlesValidityProofData>() < room);
    assert!(size_of::<PercentageWithCapProofData>() < room);
    assert!(size_of::<BatchedGroupedCiphertext2HandlesValidityProofData>() < room);
    assert!(
        size_of::<BatchedRangeProofU64Data>() > 800,
        "staged through Record"
    );
    assert!(
        size_of::<BatchedRangeProofU256Data>() > room,
        "cannot fit a transaction at all"
    );
}
