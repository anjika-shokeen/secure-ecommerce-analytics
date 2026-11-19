"""Phase 3 - Anonymization / pseudonymization pipeline.

Reads the Phase 2 classification JSON and applies one technique per tier:

    DIRECT_IDENTIFIER   -> SHA-256 hash with salt   (not reversible, still joinable)
    SENSITIVE_ATTRIBUTE -> Fernet encryption        (reversible only with the key)
                           + masked display value (**** **** **** 1234)
    QUASI_IDENTIFIER    -> generalization           (address redacted, date -> year-month)
    NON_SENSITIVE       -> untouched

Outputs (in data/):
    customers_anonymized.csv        safe for analysts
    customers_encrypted_lookup.csv  encrypted vault (hashed id + encrypted card)
    customers_secure.key            the Fernet key  (never commit this file!)

Run:  python src/anonymizer.py
"""
import hashlib
import json
from pathlib import Path

import pandas as pd
from cryptography.fernet import Fernet

from data_loader import load_customers

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "reports"

KEY_PATH = DATA_DIR / "customers_secure.key"
LOOKUP_PATH = DATA_DIR / "customers_encrypted_lookup.csv"
ANONYMIZED_PATH = DATA_DIR / "customers_anonymized.csv"

# LIMITATION (documented in SECURITY_WRITEUP.md): the salt is hardcoded for the
# demo. In production it belongs in a secrets manager, not in source code.
HASH_SALT = "ecom-demo-salt-2026"


# ---- the four techniques ----------------------------------------------------
def hash_value(value) -> str:
    """SHA-256(salt + value), shortened to 16 hex characters for readability."""
    return hashlib.sha256((HASH_SALT + str(value)).encode()).hexdigest()[:16]


def mask_card(card: str) -> str:
    """4532123412343107 -> **** **** **** 3107"""
    digits = "".join(ch for ch in str(card) if ch.isdigit())
    return f"**** **** **** {digits[-4:]}"


def generalize_date(value: str) -> str:
    """2025-07-31 -> 2025-07"""
    return str(value)[:7]


def redact_address(_value: str) -> str:
    return "[REDACTED - see city/country]"


# How each quasi-identifier is generalized. city and country are left as they are
# (low re-identification risk on their own), so they are not listed here.
GENERALIZERS = {"address": redact_address, "signup_date": generalize_date}


# ---- key handling -----------------------------------------------------------
def load_or_create_key() -> bytes:
    DATA_DIR.mkdir(exist_ok=True)
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    key = Fernet.generate_key()
    KEY_PATH.write_bytes(key)
    return key


def get_fernet() -> Fernet:
    return Fernet(load_or_create_key())


# ---- controlled decryption (used by the Admin screen) -----------------------
def decrypt_field(hashed_customer_id: str, column: str = "card_number") -> str:
    """Return the plaintext for one customer. Caller must check RBAC and log it."""
    lookup = pd.read_csv(LOOKUP_PATH, dtype=str)
    row = lookup[lookup["hashed_customer_id"] == hashed_customer_id]
    if row.empty:
        raise KeyError(f"No encrypted record for {hashed_customer_id}")
    token = row.iloc[0][f"{column}_encrypted"]
    return get_fernet().decrypt(token.encode()).decode()


# ---- the pipeline -----------------------------------------------------------
def load_classification(name: str) -> dict:
    with open(REPORT_DIR / f"{name}_classification.json") as f:
        return {r["column"]: r["sensitivity"] for r in json.load(f)}


def anonymize_customers():
    df = load_customers()
    tiers = load_classification("customers")
    fernet = get_fernet()

    anon = pd.DataFrame(index=df.index)
    lookup = pd.DataFrame({"hashed_customer_id": df["customer_id"].map(hash_value)})

    for col in df.columns:
        tier = tiers.get(col, "NON_SENSITIVE")
        if tier == "DIRECT_IDENTIFIER":
            anon[col] = df[col].map(hash_value)
        elif tier == "SENSITIVE_ATTRIBUTE":
            anon[col] = df[col].map(mask_card)
            lookup[f"{col}_encrypted"] = df[col].map(
                lambda v: fernet.encrypt(str(v).encode()).decode())
        elif tier == "QUASI_IDENTIFIER":
            anon[col] = df[col].map(GENERALIZERS[col]) if col in GENERALIZERS else df[col]
        else:
            anon[col] = df[col]

    anon.to_csv(ANONYMIZED_PATH, index=False)
    lookup.to_csv(LOOKUP_PATH, index=False)
    return df, anon, lookup


def main():
    original, anon, lookup = anonymize_customers()
    print("Anonymization complete\n")
    print("BEFORE (customers.csv), first row:")
    print(original.iloc[0].to_string())
    print("\nAFTER (customers_anonymized.csv), first row:")
    print(anon.iloc[0].to_string())
    print("\nEncrypted lookup, first row (blob shortened):")
    first = lookup.iloc[0]
    print(f"  hashed_customer_id    : {first['hashed_customer_id']}")
    print(f"  card_number_encrypted : {first['card_number_encrypted'][:40]}...")

    # Round-trip proof: decrypt row 0 with the key and compare with the original
    plain = decrypt_field(first["hashed_customer_id"])
    print("\nRound-trip check (decrypt with key == original card):",
          plain == original.iloc[0]["card_number"])
    print(f"\nFiles written to {DATA_DIR}")
    print("REMINDER: data/customers_secure.key must never be committed to git.")


if __name__ == "__main__":
    main()
