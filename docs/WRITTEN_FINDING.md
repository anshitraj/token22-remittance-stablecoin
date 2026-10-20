# What happens if a sanctioned user moves their balance into the confidential system before the permanent delegate acts?

**Short answer:** the permanent delegate can no longer touch that money, and nothing else the
issuer holds can pull it back. What the issuer *can* still do is **freeze it in place**, refuse to
approve the account in the first place, and watch transfer amounts through the auditor key.
Seizure becomes a freeze.

Every claim below marked **(tested)** is an assertion in
[`tests/task7_sanctions_gap.rs`](../tests/task7_sanctions_gap.rs),
[`tests/task5_reissue.rs`](../tests/task5_reissue.rs) or
[`tests/task6_confidential.rs`](../tests/task6_confidential.rs), run against Token-2022 11.0.0 in
LiteSVM with real zero-knowledge proofs. Claims marked **(source)** come from reading the Token-2022
program source and are *not* exercised by a test here. Nothing was run on a live cluster.

## The gap between the two requirements

The two requirements look like they fit on one mint. They do not fully compose, because they act on
different fields of the same token account:

| | Where the balance lives | Who can move it |
|---|---|---|
| Public balance | `Account::amount` (a plain `u64`) | owner, delegate, **permanent delegate** |
| Confidential balance | `pending_balance_lo/hi` and `available_balance` (ElGamal ciphertexts) | **the owner only** |

`PermanentDelegate` is honoured by the SPL `Transfer`/`Burn` family and by nothing else. No
confidential-transfer instruction recognises it as an authority: `Deposit`, `ApplyPendingBalance`,
`Withdraw` and `Transfer` all validate against the token account's *owner* **(tested:
`the_permanent_delegate_is_not_recognised_by_confidential_instructions`, which gives the delegate
the best case: it even holds the owner's keys and builds valid proofs, and is still refused with
`OwnerMismatch`)**.

## What happens, step by step

Mallory is KYC'd, approved for confidential transfers, and holds 1,000 tokens publicly. A
sanctions order is about to land. Mallory sees it first and shields everything.

1. **Deposit moves the balance out of reach immediately.** `DepositConfidentialTokens` subtracts
   the amount from the public balance and adds it to the *pending* ciphertext. From that
   instruction on, the delegate sees `amount = 0`. It does not even need to be applied to the
   available balance first **(tested: `a_deposit_is_unreachable_even_before_it_is_applied`)**.
2. **The delegate's seizure fails.** A forced `TransferCheckedWithFee` from the permanent delegate
   fails with `InsufficientFunds`; so does a `Burn` **(tested:
   `after_shielding_the_delegate_has_nothing_to_seize`)**. The off-chain library refuses earlier,
   with `NothingToMove`.
3. **The supply does not change.** The tokens still exist, counted in the mint supply, encrypted in
   Mallory's account. They are unreachable, not destroyed.
4. **It is a race, and it is partial.** The delegate seizes whatever is *still public* when its
   transaction lands. With 600 shielded and 400 public, the delegate takes the 400 and the 600
   stay encrypted **(tested: `a_partial_shield_leaves_the_remainder_seizable`)**.

Two incidental facts make the public-balance seizure itself less clean than it sounds, and both are
tested in `task5_reissue.rs`:

- **A frozen account cannot be seized.** Token-2022 checks the frozen flag before it checks the
  authority, so seizing from a frozen account needs the freeze authority to thaw it first.
- **Seizure is a transfer, so it pays the fee.** The delegate must use `TransferCheckedWithFee`
  with the correct fee. Because the issuer holds the withdraw-withheld authority the fee flows back
  to it, but the treasury receives `amount - fee`, not `amount`.

## What the issuer still controls

| Lever | Effect on a shielded balance | Evidence |
|---|---|---|
| **Freeze authority** | A frozen account cannot `Deposit`, `ApplyPendingBalance`, `Withdraw` or `Transfer`. The balance is **locked in place**: Mallory cannot exit and cannot send it on. | tested: `freezing_locks_the_confidential_balance_but_does_not_recover_it`, `a_frozen_account_cannot_use_confidential_instructions` |
| **Manual approval** (`approve_policy = manual`) | An account never approved cannot receive confidential credits, neither deposits nor incoming confidential transfers. The issuer can screen at the door. | tested: `manual_policy_blocks_deposits_until_the_issuer_approves`, `an_unapproved_account_cannot_receive_a_confidential_transfer` |
| **Default frozen + KYC thaw** | Nothing works for a new account until the issuer thaws it. | tested (Task 4, Task 6) |
| **Owner-only `ConfigureAccount`** | Nobody, including the issuer, can opt a wallet in or out on its behalf. This cuts both ways. | tested: `only_the_owner_can_configure_even_though_anyone_could_create_the_account` |
| **Auditor ElGamal key** | Every confidential transfer carries a copy of the amount encrypted to the auditor. The auditor reads **amounts** but **not balances**, and cannot move anything. | tested: `the_auditor_reads_amounts_but_not_balances_and_cannot_move_anything` |

A freeze is **not** a seizure. It stops the money moving; it does not transfer it to the issuer.
The only road from ciphertext back to something the delegate can seize is Mallory's own signed
`Withdraw`, which re-exposes exactly the withdrawn amount **(tested:
`an_exit_back_to_the_public_balance_is_seizable_again`)**. Whether a permanent freeze satisfies a
particular sanctions regime is a legal question this work cannot answer.

## What is and is not hidden

Confidentiality here hides **amounts**, not **parties**. The accounts in every instruction are
plain addresses, so the transfer graph stays public. Three amounts are also public by construction:
the deposit, the withdrawal, and the mint supply. A sanctioned wallet that moves value to other
wallets exposes those wallets, and each of them can be frozen. Shielding buys Mallory time and
privacy of amounts, not anonymity.

## Residual risks and recommendations

1. **The window is real.** Between a designation and the freeze landing, a sanctioned holder can
   shield. Freezing first and investigating after is the only ordering that closes it. Screening
   at *approval* (the manual policy) closes it for accounts that were never approved, but not for
   wallets sanctioned after onboarding.
2. **Prefer freeze-first as the operating procedure** for sanctions hits, because it is the only
   lever that works on both the public and the confidential portion.
3. **If unilateral recovery of every balance is a hard legal requirement**, confidential transfers
   on this mint do not meet it. Token-2022 offers no issuer-forced exit from the confidential
   domain **(source: no confidential instruction accepts the permanent delegate)**. The honest
   options are to not enable confidentiality, or to enable it only for accounts the issuer has
   explicitly approved and is prepared to freeze rather than seize.
4. **Auditor key custody matters.** It is the compliance team's only view into confidential
   activity. Rotating it (`UpdateMint`) changes the key for *future* transfers; transfers already
   made stay encrypted to the old key **(source, by construction of the ciphertexts; not tested)**.
5. **Token-2022's `Pausable` extension** is checked in the confidential deposit and transfer paths
   **(source)**. It is mint-wide, not per wallet, and adding it means another re-issue, so it is a
   blunt emergency stop rather than a sanctions tool. Not evaluated here.
6. **The fee path also moves into ciphertext.** Fees on confidential transfers are withheld as
   ciphertext and only the holder of the withdraw-withheld ElGamal key can read them. This repo does
   not implement harvesting or withdrawing those confidential fees, so issuer revenue from
   confidential transfers would accrue but not yet be collectable by this code.

## One-paragraph version

Putting seizure and confidentiality on the same mint gives the issuer a permanent delegate that can
only reach the public half of every account. A sanctioned user who shields before the order lands
puts their balance where the delegate cannot act and the owner alone can. The issuer is left with
three real levers: refuse approval up front, freeze in place, and read amounts through the auditor
key. Freezing contains the funds without recovering them, so "seizure" quietly becomes "freeze" for
anything shielded in time.
