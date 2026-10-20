//! Minimal client for the SPL Record program.
//!
//! A confidential transfer on a fee-bearing mint needs a
//! `BatchedRangeProofU256`, whose proof data is a little over 1 KiB: bigger than
//! what fits in a transaction next to the instruction metadata (1232 bytes). The
//! ZK ElGamal Proof program can therefore read the proof from an account
//! instead of from instruction data. That account is created and filled through
//! the Record program, in several transactions, then closed again.
//!
//! The instruction encodings below mirror `spl-record` 0.4.0
//! (`solana-program/record`). They are hand-rolled to keep this crate free of a
//! second, differently versioned `Pubkey` type.

use {
    crate::Pubkey,
    solana_instruction::{AccountMeta, Instruction},
    solana_system_interface::instruction as system_instruction,
};

/// `recr1L3PCGKLbckBqMNcJhuuyU1zgo8nBhfLVsJNwr5`
pub const RECORD_PROGRAM_ID: Pubkey =
    Pubkey::from_str_const("recr1L3PCGKLbckBqMNcJhuuyU1zgo8nBhfLVsJNwr5");

/// Record accounts start with `version: u8` and `authority: Pubkey`.
/// The writable payload begins after that header.
pub const RECORD_HEADER_LEN: usize = 33;

/// Largest payload per `Write` that still fits a transaction comfortably.
pub const WRITE_CHUNK_LEN: usize = 900;

pub fn account_len(data_len: usize) -> usize {
    RECORD_HEADER_LEN + data_len
}

/// `CreateAccount` for a record account owned by the Record program.
pub fn create(
    payer: &Pubkey,
    record_account: &Pubkey,
    data_len: usize,
    rent_exempt: impl Fn(usize) -> u64,
) -> Instruction {
    let space = account_len(data_len);
    system_instruction::create_account(
        payer,
        record_account,
        rent_exempt(space),
        space as u64,
        &RECORD_PROGRAM_ID,
    )
}

pub fn initialize(record_account: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction {
        program_id: RECORD_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*record_account, false),
            AccountMeta::new_readonly(*authority, false),
        ],
        data: vec![0],
    }
}

pub fn write(record_account: &Pubkey, authority: &Pubkey, offset: u64, data: &[u8]) -> Instruction {
    let mut buf = Vec::with_capacity(1 + 8 + 4 + data.len());
    buf.push(1);
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    Instruction {
        program_id: RECORD_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*record_account, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data: buf,
    }
}

pub fn close(record_account: &Pubkey, authority: &Pubkey, receiver: &Pubkey) -> Instruction {
    Instruction {
        program_id: RECORD_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*record_account, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*receiver, false),
        ],
        data: vec![3],
    }
}

/// `(offset, chunk)` pairs covering `data`.
pub fn chunks(data: &[u8]) -> impl Iterator<Item = (u64, &[u8])> {
    data.chunks(WRITE_CHUNK_LEN)
        .enumerate()
        .map(|(i, chunk)| ((i * WRITE_CHUNK_LEN) as u64, chunk))
}
