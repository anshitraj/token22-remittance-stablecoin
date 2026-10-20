//! Task 3: account and mint state is read only through `StateWithExtensions`.
//!
//! This file is the one place raw `Pack::unpack` is allowed to appear, because
//! it demonstrates *why* it is banned everywhere else. The lint test below
//! enforces the ban over `src/` and the other test files.

mod common;

use {
    common::*,
    remittance_stablecoin::{state, token_program_id},
    solana_program_pack::Pack,
    solana_signer::Signer,
    spl_token_2022_interface::{
        extension::{
            BaseStateWithExtensions, ExtensionType, StateWithExtensions,
            transfer_fee::TransferFeeConfig,
        },
        state::{Account, AccountState, Mint},
    },
    std::{
        fs,
        path::{Path, PathBuf},
    },
};

#[test]
fn mint_and_account_state_come_back_through_state_with_extensions() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let alice = env.wallet();
    let alice_ata = env.onboard(&issuer, &mint.pubkey(), &alice.pubkey(), 25 * ONE);

    let mint_view = state::fetch_mint(&env, &mint.pubkey()).unwrap();
    assert_eq!(mint_view.supply, 25 * ONE);
    assert_eq!(
        mint_view.mint_authority,
        Some(issuer.mint_authority.pubkey())
    );
    assert_eq!(
        mint_view.freeze_authority,
        Some(issuer.freeze_authority.pubkey())
    );

    let account_view = state::fetch_account(&env, &alice_ata).unwrap();
    assert_eq!(account_view.mint, mint.pubkey());
    assert_eq!(account_view.owner, alice.pubkey());
    assert_eq!(account_view.amount, 25 * ONE);
    assert_eq!(account_view.state, AccountState::Initialized);
    assert!(
        account_view
            .extensions
            .contains(&ExtensionType::ImmutableOwner)
    );
    assert!(
        account_view
            .extensions
            .contains(&ExtensionType::TransferFeeAmount)
    );
    assert_eq!(account_view.withheld_fee, Some(0));
    assert_eq!(account_view.delegate, None);
    assert_eq!(account_view.cpi_guard_enabled, None);
}

/// A raw `Pack::unpack` only accepts data of exactly the base length. Every
/// Token-2022 account with an extension is longer, so it is rejected outright.
#[test]
fn raw_unpack_rejects_every_extended_account() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let alice = env.wallet();
    let alice_ata = env.onboard(&issuer, &mint.pubkey(), &alice.pubkey(), ONE);

    let mint_data = env.svm.get_account(&mint.pubkey()).unwrap().data;
    let account_data = env.svm.get_account(&alice_ata).unwrap().data;

    assert!(mint_data.len() > Mint::LEN && account_data.len() > Account::LEN);
    assert!(
        Mint::unpack(&mint_data).is_err(),
        "raw Mint::unpack refuses an extended mint"
    );
    assert!(
        Account::unpack(&account_data).is_err(),
        "raw Account::unpack refuses an extended account"
    );

    // StateWithExtensions reads the very same bytes without complaint.
    assert!(StateWithExtensions::<Mint>::unpack(&mint_data).is_ok());
    assert!(StateWithExtensions::<Account>::unpack(&account_data).is_ok());
}

/// The workaround people reach for, truncating to the base length and using
/// `unpack_unchecked`, reads the base fields but is blind to every extension:
/// it cannot see the fee, the default state or the close authority.
/// `StateWithExtensions` also checks the account-type byte, so a token account
/// can never be mistaken for a mint (or the reverse).
#[test]
fn truncated_raw_reads_are_blind_to_extensions_and_the_typed_reader_checks_account_type() {
    let mut env = Env::new();
    let issuer = Issuer::new();
    let mint = env.create_v1_mint(&issuer);
    let alice = env.wallet();
    let alice_ata = env.onboard(&issuer, &mint.pubkey(), &alice.pubkey(), ONE);

    let mint_data = env.svm.get_account(&mint.pubkey()).unwrap().data;
    let account_data = env.svm.get_account(&alice_ata).unwrap().data;

    // The base fields survive truncation...
    let base = Mint::unpack_unchecked(&mint_data[..Mint::LEN]).unwrap();
    assert_eq!(base.supply, ONE);
    // ...but the rules this mint enforces are only visible with the TLV reader.
    let full = StateWithExtensions::<Mint>::unpack(&mint_data).unwrap();
    assert!(full.get_extension::<TransferFeeConfig>().is_ok());
    assert_eq!(full.get_extension_types().unwrap().len(), 5);

    // Account-type confusion is refused in both directions.
    assert!(StateWithExtensions::<Mint>::unpack(&account_data).is_err());
    assert!(StateWithExtensions::<Account>::unpack(&mint_data).is_err());
    assert!(state::read_mint(&account_data).is_err());
    assert!(state::read_account(&mint_data).is_err());
}

#[test]
fn nothing_in_the_crate_uses_raw_unpack() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let this_file = root.join("tests").join("task3_state.rs");

    let mut files = Vec::new();
    collect_rs_files(&root.join("src"), &mut files);
    collect_rs_files(&root.join("tests"), &mut files);
    collect_rs_files(&root.join("programs"), &mut files);
    files.retain(|file| *file != this_file);
    assert!(
        files.len() > 5,
        "lint found suspiciously few files: {files:?}"
    );

    let banned = [
        "Mint::unpack",
        "Account::unpack",
        "Multisig::unpack",
        "unpack_unchecked",
        "unpack_from_slice",
        "Pack::unpack",
        "solana_program_pack",
    ];

    let mut violations = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap();
        for (number, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue; // comments may talk about the banned calls
            }
            for pattern in banned {
                if line.contains(pattern) {
                    violations.push(format!(
                        "{}:{}: {}",
                        file.display(),
                        number + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "raw unpack found:\n{}",
        violations.join("\n")
    );
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[allow(dead_code)]
fn _token_program_is_token_2022() {
    // Keeps the import honest: every account read above is owned by Token-2022.
    let _ = token_program_id();
}
