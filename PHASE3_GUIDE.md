# Phase 3 — Anonymization / Pseudonymization Pipeline (Detailed Guide)

## Goal
Take the classification labels from Phase 2 and actually *do* something
protective with each column, producing:
- `data/customers_anonymized.csv` — safe for an analyst to see and query
- `data/customers_encrypted_lookup.csv` — encrypted vault, only decryptable
  by whoever holds the key
- `data/customers_secure.key` — the encryption key itself

## Why three different techniques for three different tiers?

| Tier | Technique | Reversible? | Why |
|---|---|---|---|
| DIRECT_IDENTIFIER (`customer_id`, `full_name`, `email`, `phone`) | SHA-256 hash + salt | No | You still need to JOIN tables on `customer_id` — hashing keeps that possible without ever exposing the real identity. You never need to turn a hash back into a name. |
| SENSITIVE_ATTRIBUTE (`card_number`) | Fernet symmetric encryption | Yes, with the key | A fraud investigation might legitimately need the real card number back. Hashing would make that impossible forever — encryption keeps it recoverable *only* for whoever holds the key. |
| QUASI_IDENTIFIER (`address`, `signup_date`) | Generalization | No (by design) | These aren't identifying alone, but combined (exact address + exact date) they can re-identify someone. Reducing precision (full address → city, exact date → year-month) is the core idea behind **k-anonymity**. |
| NON_SENSITIVE | Untouched | — | No protection needed. |

## Run it
```
python src/anonymizer.py
```
First run generates a new encryption key at `data/customers_secure.key` —
**do not commit this to git** (add it to `.gitignore`). Losing this file
means the encrypted lookup table becomes permanently unreadable, which is
exactly the point: it's the only way in.

## What to inspect
Open `data/customers_anonymized.csv` next to the original
`data/customers.csv` and compare row by row:
- `customer_id`, `full_name`, `email`, `phone` → now 16-character hashes
- `card_number` → now shows only `**** **** **** 3107` style masking
- `address` → now `[REDACTED - see city/country]`
- `signup_date` → now truncated to year-month (`2025-07` instead of
  `2025-07-31`)
- `city`, `country` → unchanged (lower re-identification risk on their own)

Then open `data/customers_encrypted_lookup.csv` — you'll see
`hashed_customer_id` next to a long encrypted blob for the card number.
That blob is useless without the key.

## Verify the round-trip yourself
Run this to prove the encryption is actually reversible (only with the
key):
```python
from cryptography.fernet import Fernet
import pandas as pd

with open("data/customers_secure.key", "rb") as f:
    fernet = Fernet(f.read())

lookup = pd.read_csv("data/customers_encrypted_lookup.csv")
row = lookup.iloc[0]
print(fernet.decrypt(row["card_number_encrypted"].encode()).decode())
```
Compare the printed value against the original `card_number` for that
customer in `customers.csv` (match by re-hashing their `customer_id` — or
just trust the earlier output, which showed the demo already working).

## Important limitations to mention in your report (this is what makes it "intermediate," not naive)
- **The salt is hardcoded** (`HASH_SALT` in `anonymizer.py`). In production
  this would live in a secrets manager (AWS Secrets Manager, Azure Key
  Vault, HashiCorp Vault), never in source code. Say this explicitly in
  your writeup — it shows you know the difference between a demo and a
  production system.
- **Generalization here is simplistic.** Real k-anonymity guarantees that
  every combination of quasi-identifiers matches at least *k* people. Our
  version just reduces precision without checking that guarantee. Tools
  like ARX (open source) do this properly — worth a sentence in your
  "future work" section.
- **Hashing without a per-user unique salt** means two customers who
  happened to have the identical name would hash identically. Using a
  global salt (as we did) versus a per-record salt is a deliberate
  trade-off: global salt keeps the hash consistent for joins across
  tables; per-record salt is more secure but breaks joinability. Explaining
  this trade-off well is worth marks.

## Next: Phase 4
We'll build a Streamlit app with two logins — **Analyst** (sees only
`customers_anonymized.csv`) and **Admin** (can decrypt specific fields
on demand, with every decryption action written to an audit log). This is
where the RBAC (role-based access control) and audit logging tie directly
into the UI, not just the backend.
