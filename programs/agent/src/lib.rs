//! A minimal on-chain automation agent for the Token-2022 stablecoin.
//!
//! The pattern: a user does **not** hand an automation service their key. They
//! `Approve` a program-controlled address as *delegate* of their token account,
//! with an allowance, and the program spends that allowance under rules the user
//! agreed to (a named operator, a fixed payee, a per-transaction cap).
//!
//! ```text
//!  user ── Init ─────────────► config PDA   (operator, payee, max_per_tx)
//!  user ── Token-2022 Approve ► delegate = config PDA, allowance = N   (direct, not via CPI)
//!  operator ── Execute ──► agent ── CPI TransferCheckedWithFee, signed by the PDA ──► Token-2022
//! ```
//!
//! The config PDA doubles as the delegate: a PDA owned by this program can sign
//! CPIs with its seeds, and holds the rules next to the authority.
//!
//! # CPI Guard
//!
//! CPI Guard exists to stop a *different* thing: a malicious program that gets
//! the **owner's** signature on a transaction and uses it, inside a CPI, to move
//! the owner's tokens. With the guard on, owner-signed transfers, burns,
//! approvals, authority changes and closes are refused when they arrive through
//! a CPI. A *delegate*-signed transfer is exactly the sanctioned way to act on
//! someone's behalf through a CPI, so the guard leaves it alone. [`Execute`]
//! therefore keeps working, unmodified, after the user turns CPI Guard on, while
//! [`OwnerPull`] (included only as the contrast) starts failing.
//!
//! [`Execute`]: Instruction::Execute
//! [`OwnerPull`]: Instruction::OwnerPull

use {
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        clock::Clock,
        entrypoint,
        entrypoint::ProgramResult,
        program::{invoke, invoke_signed},
        program_error::ProgramError,
        pubkey::Pubkey,
        rent::Rent,
        sysvar::Sysvar,
    },
    solana_system_interface::instruction as system_instruction,
    spl_token_2022_interface::{
        extension::{
            transfer_fee::{instruction::transfer_checked_with_fee, TransferFeeConfig},
            BaseStateWithExtensions, StateWithExtensions,
        },
        state::{Account, Mint},
    },
};

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

/// PDA seed prefix: `["agent", owner, source_token_account]`.
pub const CONFIG_SEED: &[u8] = b"agent";

/// `owner(32) operator(32) source(32) payee(32) max_per_tx(8) bump(1)`
pub const CONFIG_LEN: usize = 32 * 4 + 8 + 1;

/// Program-specific error codes (`ProgramError::Custom`).
#[repr(u32)]
pub enum AgentError {
    NotOperator = 0x1000,
    WrongSource = 0x1001,
    WrongPayee = 0x1002,
    OverLimit = 0x1003,
    WrongConfig = 0x1004,
    WrongTokenProgram = 0x1005,
}

impl From<AgentError> for ProgramError {
    fn from(e: AgentError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

/// Instruction tags (first data byte).
pub enum Instruction {
    /// `[owner (s,w), config PDA (w), source token account, system program]`
    /// data: `operator(32) payee(32) max_per_tx(8)`
    Init = 0,
    /// `[operator (s), config PDA, source (w), mint, payee (w), token program]`
    /// data: `amount(8)`
    Execute = 1,
    /// Contrast only. `[owner (s), source (w), mint, destination (w), token program]`
    /// data: `amount(8)`. Moves the *owner's* funds using the owner's signature,
    /// inside a CPI. This is what CPI Guard blocks.
    OwnerPull = 2,
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((0, rest)) => init(program_id, accounts, rest),
        Some((1, rest)) => execute(program_id, accounts, rest),
        Some((2, rest)) => owner_pull(accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn read_pubkey(data: &[u8], at: usize) -> Result<Pubkey, ProgramError> {
    let bytes: [u8; 32] = data
        .get(at..at + 32)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    Ok(Pubkey::new_from_array(bytes))
}

fn read_u64(data: &[u8], at: usize) -> Result<u64, ProgramError> {
    let bytes: [u8; 8] = data
        .get(at..at + 8)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    Ok(u64::from_le_bytes(bytes))
}

fn check_token_program(token_program: &AccountInfo) -> ProgramResult {
    if *token_program.key != spl_token_2022_interface::id() {
        return Err(AgentError::WrongTokenProgram.into());
    }
    Ok(())
}

fn init(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let accounts = &mut accounts.iter();
    let owner = next_account_info(accounts)?;
    let config = next_account_info(accounts)?;
    let source = next_account_info(accounts)?;
    let system_program = next_account_info(accounts)?;

    if !owner.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let operator = read_pubkey(data, 0)?;
    let payee = read_pubkey(data, 32)?;
    let max_per_tx = read_u64(data, 64)?;

    // The source must really be the owner's Token-2022 account.
    if *source.owner != spl_token_2022_interface::id() {
        return Err(ProgramError::IncorrectProgramId);
    }
    {
        let source_data = source.try_borrow_data()?;
        let source_state = StateWithExtensions::<Account>::unpack(&source_data)?;
        if source_state.base.owner != *owner.key {
            return Err(ProgramError::IllegalOwner);
        }
    }

    let (expected, bump) = Pubkey::find_program_address(
        &[CONFIG_SEED, owner.key.as_ref(), source.key.as_ref()],
        program_id,
    );
    if expected != *config.key {
        return Err(AgentError::WrongConfig.into());
    }

    invoke_signed(
        &system_instruction::create_account(
            owner.key,
            config.key,
            Rent::get()?.minimum_balance(CONFIG_LEN),
            CONFIG_LEN as u64,
            program_id,
        ),
        &[owner.clone(), config.clone(), system_program.clone()],
        &[&[
            CONFIG_SEED,
            owner.key.as_ref(),
            source.key.as_ref(),
            &[bump],
        ]],
    )?;

    let mut out = config.try_borrow_mut_data()?;
    out[0..32].copy_from_slice(owner.key.as_ref());
    out[32..64].copy_from_slice(operator.as_ref());
    out[64..96].copy_from_slice(source.key.as_ref());
    out[96..128].copy_from_slice(payee.as_ref());
    out[128..136].copy_from_slice(&max_per_tx.to_le_bytes());
    out[136] = bump;
    Ok(())
}

/// Decimals and the fee for `amount`, from the mint's *current* schedule.
///
/// The fee is computed on chain with `calculate_epoch_fee(Clock::epoch, ..)`
/// rather than passed in, so the agent can never be tricked into signing a
/// transfer with a stale or attacker-chosen fee.
fn decimals_and_fee(mint: &AccountInfo, amount: u64) -> Result<(u8, u64), ProgramError> {
    let mint_data = mint.try_borrow_data()?;
    let mint_state = StateWithExtensions::<Mint>::unpack(&mint_data)?;
    let fee = match mint_state.get_extension::<TransferFeeConfig>() {
        Ok(config) => config
            .calculate_epoch_fee(Clock::get()?.epoch, amount)
            .ok_or(ProgramError::ArithmeticOverflow)?,
        Err(_) => 0,
    };
    Ok((mint_state.base.decimals, fee))
}

fn execute(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let accounts = &mut accounts.iter();
    let operator = next_account_info(accounts)?;
    let config = next_account_info(accounts)?;
    let source = next_account_info(accounts)?;
    let mint = next_account_info(accounts)?;
    let payee = next_account_info(accounts)?;
    let token_program = next_account_info(accounts)?;

    let amount = read_u64(data, 0)?;
    check_token_program(token_program)?;

    if config.owner != program_id || config.data_len() != CONFIG_LEN {
        return Err(AgentError::WrongConfig.into());
    }
    let (owner, configured_operator, configured_source, configured_payee, max_per_tx, bump) = {
        let c = config.try_borrow_data()?;
        (
            read_pubkey(&c, 0)?,
            read_pubkey(&c, 32)?,
            read_pubkey(&c, 64)?,
            read_pubkey(&c, 96)?,
            read_u64(&c, 128)?,
            c[136],
        )
    };

    // The PDA must be the one derived for this exact owner and source.
    let expected = Pubkey::create_program_address(
        &[
            CONFIG_SEED,
            owner.as_ref(),
            configured_source.as_ref(),
            &[bump],
        ],
        program_id,
    )
    .map_err(|_| ProgramError::from(AgentError::WrongConfig))?;
    if expected != *config.key {
        return Err(AgentError::WrongConfig.into());
    }

    if !operator.is_signer || *operator.key != configured_operator {
        return Err(AgentError::NotOperator.into());
    }
    if *source.key != configured_source {
        return Err(AgentError::WrongSource.into());
    }
    if *payee.key != configured_payee {
        return Err(AgentError::WrongPayee.into());
    }
    if amount > max_per_tx {
        return Err(AgentError::OverLimit.into());
    }

    let (decimals, fee) = decimals_and_fee(mint, amount)?;

    // `config` is the delegate and the authority of the transfer. The PDA signs
    // with its seeds; nobody's private key is involved.
    let ix = transfer_checked_with_fee(
        token_program.key,
        source.key,
        mint.key,
        payee.key,
        config.key,
        &[],
        amount,
        decimals,
        fee,
    )?;
    invoke_signed(
        &ix,
        &[
            source.clone(),
            mint.clone(),
            payee.clone(),
            config.clone(),
            token_program.clone(),
        ],
        &[&[
            CONFIG_SEED,
            owner.as_ref(),
            configured_source.as_ref(),
            &[bump],
        ]],
    )
}

fn owner_pull(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let accounts = &mut accounts.iter();
    let owner = next_account_info(accounts)?;
    let source = next_account_info(accounts)?;
    let mint = next_account_info(accounts)?;
    let destination = next_account_info(accounts)?;
    let token_program = next_account_info(accounts)?;

    let amount = read_u64(data, 0)?;
    check_token_program(token_program)?;
    let (decimals, fee) = decimals_and_fee(mint, amount)?;

    let ix = transfer_checked_with_fee(
        token_program.key,
        source.key,
        mint.key,
        destination.key,
        owner.key,
        &[],
        amount,
        decimals,
        fee,
    )?;
    // The owner signed the outer transaction, so their signature rides along
    // into this CPI. That is precisely the pattern CPI Guard refuses.
    invoke(
        &ix,
        &[
            source.clone(),
            mint.clone(),
            destination.clone(),
            owner.clone(),
            token_program.clone(),
        ],
    )
}
