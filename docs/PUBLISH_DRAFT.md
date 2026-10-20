# Ready-to-post drafts

Optional deliverable: a link to a published version of the written finding. Nothing here has been
posted. Edit, add the repo link, and publish under your own name.

Full write-up: [`WRITTEN_FINDING.md`](WRITTEN_FINDING.md)

---

## X thread

**1/**
Put "regulators can seize from sanctioned wallets" and "users want hidden transfer amounts" on the
same Token-2022 mint and they don't fully compose. I built it and tested it. Thread on the gap. 🧵

**2/**
The issuer's seizure tool is the PermanentDelegate. It can transfer or burn from ANY token account
without the owner signing.

But it only works on the public balance, `Account::amount`.

**3/**
Confidential balances are ElGamal ciphertexts. No confidential-transfer instruction (Deposit,
ApplyPending, Withdraw, Transfer) recognises the permanent delegate as an authority. Only the owner
can move them.

I gave the delegate the owner's keys and valid proofs. Still refused: OwnerMismatch.

**4/**
So if a sanctioned user shields their balance BEFORE the delegate acts:

• the deposit empties the public balance instantly
• the delegate's transfer fails with InsufficientFunds
• supply is unchanged: the tokens exist, just unreachable

It's a race, and a partial one: the delegate keeps whatever is still public.

**5/**
What the issuer still has:
• freeze authority: locks the confidential balance in place
• manual approval: never approved = can't receive confidential credits
• auditor key: reads transfer AMOUNTS (not balances)

Freezing contains the funds. It does not recover them. Seizure quietly becomes a freeze.

**6/**
Also: confidentiality hides amounts, not parties. The graph stays public, and every downstream
wallet can be frozen too.

Code, 53 passing tests with real ZK proofs, and the write-up: <repo link>

---

## LinkedIn

**Seizure and confidentiality on one stablecoin mint: where they stop composing**

For a Week 4 Solana assignment I built a remittance stablecoin on Token-2022 (transfer fee,
default-frozen accounts for KYC, on-chain metadata, a close authority) and then re-issued it with a
permanent delegate for seizure and confidential transfers for hidden amounts. The result is a
53-test suite with real zero-knowledge proofs.

The interesting finding is the gap between the two requirements. The permanent delegate can move
tokens from any account, but only from the public balance. Confidential balances are ciphertext
that only the owner can move, and no confidential instruction recognises the delegate. A sanctioned
user who shields before the order lands puts their funds where the issuer's seizure power cannot
reach.

What the issuer keeps: freezing in place (it blocks every confidential operation), refusing to
approve an account for confidential transfers, and reading transfer amounts through an auditor key.
A freeze contains the money without recovering it, so for anything shielded in time, "seizure"
becomes "freeze". Confidentiality here also hides amounts, not parties, so the transfer graph stays
public.

Every claim is backed by a test. Repo and write-up: <repo link>

#Solana #Token2022 #Compliance #ZeroKnowledge
