//! Shared test harness: a LiteSVM-backed chain plus helpers for signing,
//! sending and asserting on Token-2022 errors.
#![allow(dead_code, clippy::result_large_err)]

use {
    litesvm::{
        LiteSVM,
        types::{FailedTransactionMetadata, TransactionMetadata},
    },
    remittance_stablecoin::{
        ChainReader, Pubkey,
        accounts::{ata_address, create_ata},
        confidential::{self, ConfidentialKeys, Plan, Step},
        mint::{self, ApprovePolicy, MetadataParams, MintParams, ReissueParams},
        record::RECORD_PROGRAM_ID,
        state, token_program_id,
    },
    solana_clock::Clock,
    solana_instruction::Instruction,
    solana_instruction_error::InstructionError,
    solana_keypair::Keypair,
    solana_message::Message,
    solana_signer::Signer,
    solana_transaction::Transaction,
    solana_transaction_error::TransactionError,
    solana_zk_sdk::encryption::elgamal::ElGamalKeypair,
    spl_token_2022_interface::{
        error::TokenError,
        instruction::{mint_to_checked, thaw_account},
    },
};

pub type TxResult = Result<TransactionMetadata, FailedTransactionMetadata>;

/// Largest serialized transaction a validator accepts.
pub const PACKET_DATA_SIZE: usize = 1232;

pub const DECIMALS: u8 = 6;
/// 1.00 token in base units.
pub const ONE: u64 = 1_000_000;
/// 1% transfer fee, capped at 2.5 tokens.
pub const FEE_BPS: u16 = 100;
pub const MAX_FEE: u64 = 2_500_000;

/// Every authority the stablecoin defines, as a separate key so the tests can
/// prove each one only does its own job.
pub struct Issuer {
    pub mint_authority: Keypair,
    pub freeze_authority: Keypair,
    pub close_authority: Keypair,
    pub fee_config_authority: Keypair,
    pub withdraw_withheld_authority: Keypair,
    pub metadata_authority: Keypair,
    pub permanent_delegate: Keypair,
    pub confidential_authority: Keypair,
}

impl Issuer {
    pub fn new() -> Self {
        Self {
            mint_authority: Keypair::new(),
            freeze_authority: Keypair::new(),
            close_authority: Keypair::new(),
            fee_config_authority: Keypair::new(),
            withdraw_withheld_authority: Keypair::new(),
            metadata_authority: Keypair::new(),
            permanent_delegate: Keypair::new(),
            confidential_authority: Keypair::new(),
        }
    }

    pub fn mint_params(&self) -> MintParams {
        MintParams {
            decimals: DECIMALS,
            mint_authority: self.mint_authority.pubkey(),
            freeze_authority: self.freeze_authority.pubkey(),
            close_authority: self.close_authority.pubkey(),
            transfer_fee_config_authority: self.fee_config_authority.pubkey(),
            withdraw_withheld_authority: self.withdraw_withheld_authority.pubkey(),
            fee_basis_points: FEE_BPS,
            maximum_fee: MAX_FEE,
            metadata_update_authority: self.metadata_authority.pubkey(),
            metadata: MetadataParams {
                name: "Remit Dollar".to_string(),
                symbol: "RMTD".to_string(),
                uri: "https://remit.example/rmtd.json".to_string(),
                additional: vec![
                    ("issuer".to_string(), "Remit Payments Ltd.".to_string()),
                    (
                        "kyc_policy".to_string(),
                        "https://remit.example/kyc".to_string(),
                    ),
                ],
            },
        }
    }
}

/// ElGamal keys the v2 mint is configured with.
pub struct ConfidentialAuthorities {
    /// Receives a copy of every confidential transfer amount.
    pub auditor: ElGamalKeypair,
    /// Decrypts fees withheld by confidential transfers.
    pub withdraw_withheld: ElGamalKeypair,
}

impl ConfidentialAuthorities {
    pub fn new() -> Self {
        Self {
            auditor: ElGamalKeypair::new_rand(),
            withdraw_withheld: ElGamalKeypair::new_rand(),
        }
    }
}

pub struct Env {
    pub svm: LiteSVM,
    pub payer: Keypair,
}

impl ChainReader for Env {
    fn account_data(&self, address: &Pubkey) -> Option<Vec<u8>> {
        self.svm.get_account(address).map(|account| account.data)
    }

    fn current_epoch(&self) -> u64 {
        self.svm.get_sysvar::<Clock>().epoch
    }
}

impl Env {
    pub fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.add_program_from_file(
            RECORD_PROGRAM_ID,
            concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/spl_record.so"),
        )
        .expect("load fixtures/spl_record.so");

        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10_000 * 1_000_000_000)
            .expect("airdrop payer");
        Self { svm, payer }
    }

    pub fn rent(&self, len: usize) -> u64 {
        self.svm.minimum_balance_for_rent_exemption(len)
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.epoch = epoch;
        self.svm.set_sysvar(&clock);
    }

    /// Sign with the fee payer plus `signers`, refuse anything a real validator
    /// would reject for size, and send.
    pub fn send(&mut self, instructions: &[Instruction], signers: &[&Keypair]) -> TxResult {
        let mut all: Vec<&Keypair> = vec![&self.payer];
        for signer in signers {
            if !all.iter().any(|k| k.pubkey() == signer.pubkey()) {
                all.push(signer);
            }
        }
        let blockhash = self.svm.latest_blockhash();
        let message =
            Message::new_with_blockhash(instructions, Some(&self.payer.pubkey()), &blockhash);
        // Sign with exactly the keys the message requires. Callers pass every
        // key they *might* need (e.g. the token owner) and steps that do not
        // involve that key simply ignore it.
        let required: Vec<Pubkey> = message
            .account_keys
            .iter()
            .take(message.header.num_required_signatures as usize)
            .copied()
            .collect();
        all.retain(|keypair| required.contains(&keypair.pubkey()));
        let tx = Transaction::new(&all[..], message, blockhash);

        let wire_len = 1 + tx.signatures.len() * 64 + tx.message_data().len();
        assert!(
            wire_len <= PACKET_DATA_SIZE,
            "transaction is {wire_len} bytes, over the {PACKET_DATA_SIZE}-byte packet limit"
        );

        let result = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        result
    }

    pub fn send_ok(
        &mut self,
        instructions: &[Instruction],
        signers: &[&Keypair],
    ) -> TransactionMetadata {
        match self.send(instructions, signers) {
            Ok(meta) => meta,
            Err(failed) => panic!(
                "transaction failed: {:?}\n{}",
                failed.err,
                failed.meta.pretty_logs()
            ),
        }
    }

    pub fn send_err(
        &mut self,
        instructions: &[Instruction],
        signers: &[&Keypair],
    ) -> FailedTransactionMetadata {
        match self.send(instructions, signers) {
            Ok(meta) => panic!("transaction unexpectedly succeeded\n{}", meta.pretty_logs()),
            Err(failed) => failed,
        }
    }

    /// Send one planned [`Step`]: payer + owner + the step's own keypairs.
    pub fn run_step(&mut self, step: &Step, owner: &Keypair) -> TransactionMetadata {
        let mut signers: Vec<&Keypair> = vec![owner];
        signers.extend(step.extra_signers.iter());
        match self.send(&step.instructions, &signers) {
            Ok(meta) => meta,
            Err(failed) => panic!(
                "step '{}' failed: {:?}\n{}",
                step.label,
                failed.err,
                failed.meta.pretty_logs()
            ),
        }
    }

    /// Run setup, main and cleanup of a plan; returns the main step's metadata.
    pub fn run_plan(&mut self, plan: &Plan, owner: &Keypair) -> TransactionMetadata {
        for step in &plan.setup {
            self.run_step(step, owner);
        }
        let meta = self.run_step(&plan.main, owner);
        self.run_step(&plan.cleanup, owner);
        meta
    }

    pub fn wallet(&mut self) -> Keypair {
        let wallet = Keypair::new();
        self.svm
            .airdrop(&wallet.pubkey(), 10 * 1_000_000_000)
            .expect("airdrop wallet");
        wallet
    }

    // -- mint --------------------------------------------------------------

    pub fn create_v1_mint(&mut self, issuer: &Issuer) -> Keypair {
        let mint = Keypair::new();
        let ixs = mint::create_mint_v1(
            &self.payer.pubkey(),
            &mint.pubkey(),
            &issuer.mint_params(),
            |len| self.svm.minimum_balance_for_rent_exemption(len),
        )
        .expect("build v1 mint");
        self.send_ok(
            &ixs,
            &[&mint, &issuer.mint_authority, &issuer.metadata_authority],
        );
        mint
    }

    /// Task 5: the re-issued mint (new address, v1 extensions carried forward,
    /// plus PermanentDelegate and manual-approval confidential transfers).
    pub fn create_v2_mint(&mut self, issuer: &Issuer, keys: &ConfidentialAuthorities) -> Keypair {
        let mint = Keypair::new();
        let reissue = ReissueParams {
            permanent_delegate: issuer.permanent_delegate.pubkey(),
            confidential_transfer_authority: issuer.confidential_authority.pubkey(),
            approve_policy: ApprovePolicy::Manual,
            auditor_elgamal_pubkey: Some((*keys.auditor.pubkey()).into()),
            withdraw_withheld_elgamal_pubkey: (*keys.withdraw_withheld.pubkey()).into(),
        };
        let ixs = mint::create_mint_v2(
            &self.payer.pubkey(),
            &mint.pubkey(),
            &issuer.mint_params(),
            &reissue,
            |len| self.svm.minimum_balance_for_rent_exemption(len),
        )
        .expect("build v2 mint");
        self.send_ok(
            &ixs,
            &[&mint, &issuer.mint_authority, &issuer.metadata_authority],
        );
        mint
    }

    // -- token accounts ----------------------------------------------------

    /// Anyone can create anyone's ATA; here the fee payer does.
    pub fn create_ata_for(&mut self, owner: &Pubkey, mint: &Pubkey) -> Pubkey {
        let ix = create_ata(&self.payer.pubkey(), owner, mint);
        self.send_ok(&[ix], &[]);
        ata_address(owner, mint)
    }

    pub fn thaw(&mut self, issuer: &Issuer, account: &Pubkey, mint: &Pubkey) {
        let ix = thaw_account(
            &token_program_id(),
            account,
            mint,
            &issuer.freeze_authority.pubkey(),
            &[],
        )
        .unwrap();
        self.send_ok(&[ix], &[&issuer.freeze_authority]);
    }

    /// Create + thaw + fund: a KYC'd wallet holding `amount` base units.
    pub fn onboard(
        &mut self,
        issuer: &Issuer,
        mint: &Pubkey,
        owner: &Pubkey,
        amount: u64,
    ) -> Pubkey {
        let account = self.create_ata_for(owner, mint);
        self.thaw(issuer, &account, mint);
        if amount > 0 {
            self.mint_to(issuer, mint, &account, amount);
        }
        account
    }

    pub fn mint_to(&mut self, issuer: &Issuer, mint: &Pubkey, account: &Pubkey, amount: u64) {
        let ix = mint_to_checked(
            &token_program_id(),
            mint,
            account,
            &issuer.mint_authority.pubkey(),
            &[],
            amount,
            DECIMALS,
        )
        .unwrap();
        self.send_ok(&[ix], &[&issuer.mint_authority]);
    }

    /// Everything a wallet needs before it can use confidential transfers:
    /// ATA, ConfigureAccount (owner), ApproveAccount (issuer), thaw (KYC).
    /// Returns the account and the owner's confidential keys.
    pub fn enable_confidential(
        &mut self,
        issuer: &Issuer,
        mint: &Pubkey,
        owner: &Keypair,
    ) -> (Pubkey, ConfidentialKeys) {
        let account = self.create_ata_for(&owner.pubkey(), mint);
        let keys = ConfidentialKeys::derive(owner).expect("derive keys");

        let payer = self.payer.pubkey();
        let configure =
            confidential::configure_account(self, &payer, &owner.pubkey(), &account, &keys)
                .expect("configure");
        self.send_ok(&configure, &[owner]);

        let approve =
            confidential::approve_account(&account, mint, &issuer.confidential_authority.pubkey())
                .expect("approve");
        self.send_ok(&[approve], &[&issuer.confidential_authority]);

        self.thaw(issuer, &account, mint);
        (account, keys)
    }

    /// Deposit then apply: public balance -> available confidential balance.
    pub fn shield(
        &mut self,
        owner: &Keypair,
        account: &Pubkey,
        keys: &ConfidentialKeys,
        amount: u64,
    ) {
        let deposit =
            confidential::deposit(self, account, &owner.pubkey(), amount).expect("deposit");
        self.send_ok(&[deposit], &[owner]);
        self.apply_pending(owner, account, keys);
    }

    pub fn apply_pending(&mut self, owner: &Keypair, account: &Pubkey, keys: &ConfidentialKeys) {
        let apply = confidential::apply_pending_balance(self, account, &owner.pubkey(), keys)
            .expect("apply pending");
        self.send_ok(&[apply], &[owner]);
    }

    pub fn balance(&self, account: &Pubkey) -> u64 {
        state::fetch_account(self, account)
            .expect("read account")
            .amount
    }

    pub fn supply(&self, mint: &Pubkey) -> u64 {
        state::fetch_mint(self, mint).expect("read mint").supply
    }
}

// -- error assertions --------------------------------------------------------

/// The instruction error code of a failed transaction, if it was a custom one.
pub fn custom_code(failed: &FailedTransactionMetadata) -> Option<u32> {
    match &failed.err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => Some(*code),
        _ => None,
    }
}

pub fn assert_token_error(failed: &FailedTransactionMetadata, expected: TokenError) {
    let code = expected.clone() as u32;
    assert_eq!(
        custom_code(failed),
        Some(code),
        "expected {expected:?}, got {:?}\n{}",
        failed.err,
        failed.meta.pretty_logs()
    );
}

pub fn assert_instruction_error(failed: &FailedTransactionMetadata, expected: InstructionError) {
    match &failed.err {
        TransactionError::InstructionError(_, actual) => assert_eq!(
            *actual,
            expected,
            "wrong instruction error\n{}",
            failed.meta.pretty_logs()
        ),
        other => panic!("expected instruction error {expected:?}, got {other:?}"),
    }
}
