use {
    crate::Pubkey, solana_program_error::ProgramError,
    spl_token_2022_interface::extension::ExtensionType,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("program error: {0}")]
    Program(#[from] ProgramError),

    #[error("account {0} was not found on chain")]
    AccountNotFound(Pubkey),

    #[error("account does not carry the {0:?} extension")]
    MissingExtension(ExtensionType),

    #[error("transfer fee calculation overflowed")]
    FeeOverflow,

    #[error("account {0} is not frozen, nothing to thaw")]
    NotFrozen(Pubkey),

    #[error("mint has no freeze authority, accounts could never be thawed")]
    NoFreezeAuthority,

    #[error("{signer} is not the {role} configured on the mint")]
    WrongAuthority { signer: Pubkey, role: &'static str },

    #[error("account {0} holds no public balance to move")]
    NothingToMove(Pubkey),

    #[error("confidential transfer error: {0}")]
    Confidential(String),

    #[error("zero-knowledge proof generation failed: {0}")]
    Proof(String),
}
