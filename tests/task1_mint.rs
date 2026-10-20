//! Task 1: a mint that stacks TransferFeeConfig, MetadataPointer (at the mint
//! itself), DefaultAccountState(Frozen) and MintCloseAuthority.

mod common;

use {
    common::*,
    remittance_stablecoin::{
        mint::{self, MintLayout},
        state::{self},
        token_program_id,
    },
    solana_instruction_error::InstructionError,
    solana_keypair::Keypair,
    solana_signer::Signer,
    spl_token_2022_interface::{
        extension::ExtensionType,
        instruction::{burn_checked, close_account},
        state::AccountState,
    },
};

#[test]
fn mint_has_exactly_the_four_extensions_and_is_sized_by_the_calculator() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);

    let view = state::fetch_mint(&env, &mint.pubkey()).unwrap();

    // The four required extensions are present, plus the variable-length
    // TokenMetadata that lives in the same account.
    for expected in mint::v1_extensions() {
        assert!(
            view.extensions.contains(&expected),
            "{expected:?} missing from {:?}",
            view.extensions
        );
    }
    assert_eq!(
        view.extensions.len(),
        4 + 1,
        "four fixed extensions + TokenMetadata"
    );
    assert!(view.extensions.contains(&ExtensionType::TokenMetadata));

    // Sizing: the account was allocated with try_calculate_account_len and
    // then grew by exactly the metadata TLV when the metadata was written.
    let layout: MintLayout = mint::mint_layout(
        &mint.pubkey(),
        &mint::v1_extensions(),
        &issuer.mint_params().metadata,
    )
    .unwrap();
    let account = env.svm.get_account(&mint.pubkey()).unwrap();
    assert_eq!(account.owner, token_program_id());
    assert_eq!(account.data.len(), layout.funded_len);
    assert_eq!(
        layout.allocated_len,
        mint::mint_account_len(&mint::v1_extensions()).unwrap()
    );
    assert!(
        account.lamports >= env.rent(account.data.len()),
        "mint must be rent exempt at its final size"
    );
}

#[test]
fn extension_configuration_is_what_was_asked_for() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let view = state::fetch_mint(&env, &mint.pubkey()).unwrap();

    // TransferFeeConfig
    let fee = view.transfer_fee.expect("transfer fee config");
    assert_eq!(fee.newer.basis_points, FEE_BPS);
    assert_eq!(fee.newer.maximum_fee, MAX_FEE);
    assert_eq!(
        fee.config_authority,
        Some(issuer.fee_config_authority.pubkey())
    );
    assert_eq!(
        fee.withdraw_withheld_authority,
        Some(issuer.withdraw_withheld_authority.pubkey())
    );

    // MetadataPointer points at the mint itself, and the metadata is really there.
    assert_eq!(view.metadata_pointer_address, Some(mint.pubkey()));
    assert_eq!(
        view.metadata_pointer_authority,
        Some(issuer.metadata_authority.pubkey())
    );
    let metadata = view.token_metadata.expect("on-chain metadata");
    assert_eq!(metadata.mint, mint.pubkey());
    assert_eq!(metadata.name, "Remit Dollar");
    assert_eq!(metadata.symbol, "RMTD");
    assert_eq!(metadata.uri, "https://remit.example/rmtd.json");
    assert!(
        metadata
            .additional_metadata
            .contains(&("issuer".to_string(), "Remit Payments Ltd.".to_string()))
    );

    // DefaultAccountState(Frozen) + the freeze authority that can undo it.
    assert_eq!(view.default_account_state, Some(AccountState::Frozen));
    assert_eq!(
        view.freeze_authority,
        Some(issuer.freeze_authority.pubkey())
    );

    // MintCloseAuthority
    assert_eq!(view.close_authority, Some(issuer.close_authority.pubkey()));
    assert_eq!(view.decimals, DECIMALS);
}

#[test]
fn every_extension_initializer_precedes_initialize_mint() {
    let env = Env::new();
    let issuer = Issuer::new();
    let mint = Keypair::new();

    let ixs = mint::create_mint_v1(
        &env.payer.pubkey(),
        &mint.pubkey(),
        &issuer.mint_params(),
        |len| env.rent(len),
    )
    .unwrap();
    assert!(mint::initializers_precede_initialize_mint(&ixs).unwrap());

    // Same rule for the re-issued mint, which has three more initializers.
    let reissue = common_reissue_params();
    let ixs_v2 = mint::create_mint_v2(
        &env.payer.pubkey(),
        &mint.pubkey(),
        &issuer.mint_params(),
        &reissue(&issuer),
        |len| env.rent(len),
    )
    .unwrap();
    assert!(mint::initializers_precede_initialize_mint(&ixs_v2).unwrap());
}

/// Why the order matters: once `InitializeMint2` has run, Token-2022 refuses
/// every extension initializer.
#[test]
fn initializing_an_extension_after_the_mint_is_rejected() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = Keypair::new();

    let mut ixs = mint::create_mint_v1(
        &env.payer.pubkey(),
        &mint.pubkey(),
        &issuer.mint_params(),
        |len| env.rent(len),
    )
    .unwrap();

    // Move InitializeMint2 (the instruction right before the two metadata
    // ones) in front of the MintCloseAuthority initializer.
    let initialize_mint_at = ixs
        .iter()
        .position(|ix| {
            ix.program_id == token_program_id()
                && matches!(
                    spl_token_2022_interface::instruction::TokenInstruction::unpack(&ix.data),
                    Ok(spl_token_2022_interface::instruction::TokenInstruction::InitializeMint2 { .. })
                )
        })
        .unwrap();
    let initialize_mint = ixs.remove(initialize_mint_at);
    ixs.insert(1, initialize_mint); // right after create_account
    assert!(!mint::initializers_precede_initialize_mint(&ixs).unwrap());

    let failed = env.send_err(
        &ixs,
        &[&mint, &issuer.mint_authority, &issuer.metadata_authority],
    );
    assert_instruction_error(&failed, InstructionError::InvalidAccountData);
    assert!(
        env.svm.get_account(&mint.pubkey()).is_none(),
        "the failed transaction must leave no half-built mint behind"
    );
}

/// Why `try_calculate_account_len` matters: leave one extension out of the
/// allocation and the initializer for it cannot find room.
#[test]
fn undersized_allocation_is_rejected() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = Keypair::new();
    let params = issuer.mint_params();

    let mut ixs = mint::create_mint_v1(&env.payer.pubkey(), &mint.pubkey(), &params, |len| {
        env.rent(len)
    })
    .unwrap();

    // Re-create the first instruction with a space computed *without*
    // MintCloseAuthority.
    let short: Vec<_> = mint::v1_extensions()
        .into_iter()
        .filter(|ext| *ext != ExtensionType::MintCloseAuthority)
        .collect();
    let short_len = mint::mint_account_len(&short).unwrap();
    let full_len = mint::mint_account_len(&mint::v1_extensions()).unwrap();
    assert!(short_len < full_len);
    ixs[0] = solana_system_interface::instruction::create_account(
        &env.payer.pubkey(),
        &mint.pubkey(),
        env.rent(full_len + 400),
        short_len as u64,
        &token_program_id(),
    );

    let failed = env.send_err(
        &ixs,
        &[&mint, &issuer.mint_authority, &issuer.metadata_authority],
    );
    assert_instruction_error(&failed, InstructionError::InvalidAccountData);
}

#[test]
fn new_token_accounts_are_born_frozen() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);

    let stranger = Keypair::new().pubkey();
    let account = env.create_ata_for(&stranger, &mint.pubkey());

    let view = state::fetch_account(&env, &account).unwrap();
    assert_eq!(view.state, AccountState::Frozen);
    assert_eq!(view.owner, stranger);
    assert!(view.extensions.contains(&ExtensionType::TransferFeeAmount));
}

/// Decommissioning: the close authority can close the mint, but only at zero
/// supply, and supply includes fees still withheld in token accounts.
#[test]
fn close_authority_can_decommission_the_mint_only_at_zero_supply() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let mint_key = mint.pubkey();

    let alice = env.wallet();
    let bob = env.wallet();
    let alice_ata = env.onboard(&issuer, &mint_key, &alice.pubkey(), 100 * ONE);
    let bob_ata = env.onboard(&issuer, &mint_key, &bob.pubkey(), 0);

    // A fee-bearing transfer leaves 0.5 tokens withheld in Bob's account.
    let ix = remittance_stablecoin::transfer::transfer_with_fee(
        &env,
        &alice_ata,
        &bob_ata,
        &alice.pubkey(),
        50 * ONE,
    )
    .unwrap();
    env.send_ok(&[ix], &[&alice]);
    assert_eq!(env.balance(&bob_ata), 50 * ONE - 500_000);
    assert_eq!(
        state::fetch_account(&env, &bob_ata).unwrap().withheld_fee,
        Some(500_000)
    );

    let close_ix = close_account(
        &token_program_id(),
        &mint_key,
        &env.payer.pubkey(),
        &issuer.close_authority.pubkey(),
        &[],
    )
    .unwrap();

    // Supply is 100, so the mint cannot close.
    let failed = env.send_err(std::slice::from_ref(&close_ix), &[&issuer.close_authority]);
    assert_token_error_code(
        &failed,
        spl_token_2022_interface::error::TokenError::MintHasSupply,
    );

    // The wrong signer is rejected before the supply check matters.
    let impostor = Keypair::new();
    let impostor_ix = close_account(
        &token_program_id(),
        &mint_key,
        &env.payer.pubkey(),
        &impostor.pubkey(),
        &[],
    )
    .unwrap();
    assert!(env.send(&[impostor_ix], &[&impostor]).is_err());

    // Harvest withheld fees into the mint, pull them out, burn everything.
    let harvest = spl_token_2022_interface::extension::transfer_fee::instruction::harvest_withheld_tokens_to_mint(
        &token_program_id(),
        &mint_key,
        &[&bob_ata],
    )
    .unwrap();
    env.send_ok(&[harvest], &[]);

    let treasury = env.wallet();
    let treasury_ata = env.onboard(&issuer, &mint_key, &treasury.pubkey(), 0);
    let withdraw = spl_token_2022_interface::extension::transfer_fee::instruction::withdraw_withheld_tokens_from_mint(
        &token_program_id(),
        &mint_key,
        &treasury_ata,
        &issuer.withdraw_withheld_authority.pubkey(),
        &[],
    )
    .unwrap();
    env.send_ok(&[withdraw], &[&issuer.withdraw_withheld_authority]);
    assert_eq!(env.balance(&treasury_ata), 500_000);

    for (owner, ata) in [
        (&alice, alice_ata),
        (&bob, bob_ata),
        (&treasury, treasury_ata),
    ] {
        let amount = env.balance(&ata);
        if amount > 0 {
            let burn = burn_checked(
                &token_program_id(),
                &ata,
                &mint_key,
                &owner.pubkey(),
                &[],
                amount,
                DECIMALS,
            )
            .unwrap();
            env.send_ok(&[burn], &[owner]);
        }
    }
    assert_eq!(env.supply(&mint_key), 0);

    // Now the close authority can retire the mint, and the rent comes back.
    let before = env.svm.get_balance(&env.payer.pubkey()).unwrap();
    env.send_ok(&[close_ix], &[&issuer.close_authority]);
    assert!(
        env.svm.get_account(&mint_key).is_none(),
        "mint account is gone"
    );
    assert!(env.svm.get_balance(&env.payer.pubkey()).unwrap() > before - 10_000_000);
}

// -- local helpers -----------------------------------------------------------

fn assert_token_error_code(
    failed: &litesvm::types::FailedTransactionMetadata,
    expected: spl_token_2022_interface::error::TokenError,
) {
    assert_token_error(failed, expected);
}

fn common_reissue_params() -> impl Fn(&Issuer) -> mint::ReissueParams {
    |issuer| {
        let withdraw_withheld = solana_zk_sdk::encryption::elgamal::ElGamalKeypair::new_rand();
        mint::ReissueParams {
            permanent_delegate: issuer.permanent_delegate.pubkey(),
            confidential_transfer_authority: issuer.confidential_authority.pubkey(),
            approve_policy: mint::ApprovePolicy::Manual,
            auditor_elgamal_pubkey: None,
            withdraw_withheld_elgamal_pubkey: (*withdraw_withheld.pubkey()).into(),
        }
    }
}
