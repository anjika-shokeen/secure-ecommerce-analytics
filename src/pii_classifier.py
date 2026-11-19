"""Phase 2 - PII / data classification.

Labels every column of a dataframe as one of:
    DIRECT_IDENTIFIER, SENSITIVE_ATTRIBUTE, QUASI_IDENTIFIER, NON_SENSITIVE

Three signals each cast a weighted "vote": column name, column content (regex on
a sample of values) and uniqueness ratio. The tier with the highest score wins and
the score becomes the confidence. A reviewed allowlist lets a human override
known false positives, and low-confidence labels are flagged for human review.

Run:  python src/pii_classifier.py
"""
import json
import re
from pathlib import Path

import pandas as pd

from data_loader import load_customers, load_orders

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"

DIRECT, SENSITIVE, QUASI, NON = (
    "DIRECT_IDENTIFIER", "SENSITIVE_ATTRIBUTE", "QUASI_IDENTIFIER", "NON_SENSITIVE")

# ---- Signal 1: column-name keywords ---------------------------------------
DIRECT_ID_KEYWORDS = ["customer", "name", "email", "phone", "number", "passport", "ssn"]
SENSITIVE_KEYWORDS = ["card", "cvv", "password", "iban"]
QUASI_ID_KEYWORDS = ["address", "city", "country", "zip", "postal", "signup", "birth", "dob"]

# ---- Signal 2: content patterns --------------------------------------------
# Order matters: dates are tested BEFORE the loose phone pattern, otherwise a
# value like 2026-01-05 could be misread as a phone number.
PATTERNS = [
    ("email", re.compile(r"^[\w.+-]+@[\w-]+\.[\w.-]+$")),
    ("card_number", re.compile(r"^\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}$")),
    ("date", re.compile(r"^\d{4}-\d{2}-\d{2}$")),
    ("phone", re.compile(r"^\+?[\d\-\s().]{10,20}$")),
]
PATTERN_MATCH_RATIO = 0.8      # share of sampled values that must match
SAMPLE_SIZE = 200
UNIQUENESS_THRESHOLD = 0.95

# ---- Human review: columns a reviewer confirmed are NOT personal data ------
# 'product_name' contains the word "name" but holds product names, not people.
REVIEWED_NON_PII_COLUMNS = {"product_name"}

LOW_CONFIDENCE = 0.6
LOW_CONF_NOTE = "LOW CONFIDENCE - flag for human review before trusting this label"


def detect_content_pattern(series: pd.Series):
    """Return the name of the first pattern that most sampled values match."""
    values = series.dropna().astype(str)
    if values.empty:
        return None
    sample = values.sample(min(SAMPLE_SIZE, len(values)), random_state=0)
    for name, regex in PATTERNS:
        if sample.map(lambda v: bool(regex.match(v))).mean() >= PATTERN_MATCH_RATIO:
            return name
    return None


def classify_column(df: pd.DataFrame, col: str, use_allowlist: bool = True) -> dict:
    if use_allowlist and col in REVIEWED_NON_PII_COLUMNS:
        return {"column": col, "sensitivity": NON, "confidence": 1.0,
                "reasons": ["manually reviewed and allowlisted as non-PII"]}

    name = col.lower()
    scores = {DIRECT: 0.0, SENSITIVE: 0.0, QUASI: 0.0}
    reasons = []

    # Signal 1 - column name
    if any(k in name for k in DIRECT_ID_KEYWORDS):
        scores[DIRECT] += 0.6
        reasons.append("column name matches direct-identifier keyword")
    if any(k in name for k in SENSITIVE_KEYWORDS):
        scores[SENSITIVE] += 0.6
        reasons.append("column name matches sensitive-attribute keyword")
    if any(k in name for k in QUASI_ID_KEYWORDS):
        scores[QUASI] += 0.5
        reasons.append("column name matches quasi-identifier keyword")

    # Signal 2 - column content (text columns only)
    is_text = pd.api.types.is_string_dtype(df[col]) or df[col].dtype == object
    pattern = detect_content_pattern(df[col]) if is_text else None
    if pattern == "email":
        scores[DIRECT] += 0.99
        reasons.append("column content matches email pattern")
    elif pattern == "phone":
        scores[DIRECT] += 0.8
        reasons.append("column content matches phone pattern")
    elif pattern == "card_number":
        scores[SENSITIVE] += 0.99
        reasons.append("column content matches card_number pattern")

    # Signal 3 - uniqueness: only used when nothing else matched, and never for
    # surrogate keys such as order_id.
    if (not reasons and pattern != "date" and is_text and not name.endswith("_id")
            and df[col].nunique() / max(len(df), 1) > UNIQUENESS_THRESHOLD):
        scores[DIRECT] += 0.55
        reasons.append("almost every value is unique (>95%) - possible identifier")

    best = max(scores, key=scores.get)
    if scores[best] == 0:
        return {"column": col, "sensitivity": NON, "confidence": 1.0,
                "reasons": ["no PII signals matched"]}

    confidence = round(min(scores[best], 0.99), 2)
    if confidence < LOW_CONFIDENCE:
        reasons.append(LOW_CONF_NOTE)
    return {"column": col, "sensitivity": best, "confidence": confidence, "reasons": reasons}


def classify_dataframe(df: pd.DataFrame, use_allowlist: bool = True) -> list:
    return [classify_column(df, c, use_allowlist) for c in df.columns]


def print_report(title: str, results: list):
    print(f"\n=== {title} ===")
    for tier in (DIRECT, SENSITIVE, QUASI, NON):
        group = [r for r in results if r["sensitivity"] == tier]
        print(f"\n[{tier}] ({len(group)} columns)")
        for r in group:
            print(f"  - {r['column']:<16} confidence={r['confidence']}")
            for reason in r["reasons"]:
                print(f"        * {reason}")


def main():
    REPORT_DIR.mkdir(exist_ok=True)
    customers, orders = load_customers(), load_orders()

    # Before/after demo of the false-positive story from the report
    before = classify_column(orders, "product_name", use_allowlist=False)
    print("False-positive demo (product_name)")
    print(f"  BEFORE human review: {before['sensitivity']} (confidence {before['confidence']})")

    cust_res = classify_dataframe(customers)
    ord_res = classify_dataframe(orders)
    after = next(r for r in ord_res if r["column"] == "product_name")
    print(f"  AFTER  allowlist   : {after['sensitivity']} - {after['reasons'][0]}")

    print_report("CUSTOMERS", cust_res)
    print_report("ORDERS", ord_res)

    for fname, res in (("customers_classification.json", cust_res),
                       ("orders_classification.json", ord_res)):
        with open(REPORT_DIR / fname, "w") as f:
            json.dump(res, f, indent=2)
    print("\nSaved reports/customers_classification.json and reports/orders_classification.json")


if __name__ == "__main__":
    main()
