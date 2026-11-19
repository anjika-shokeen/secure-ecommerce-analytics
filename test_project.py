"""Automated checks - one block per row of the report's Table 5.3 (Testing and Results).

Run the pipeline first (README steps 2-6), then:   python test_project.py
Uses a temporary audit database, so logs/audit.db is not touched.
"""
import json
import sys
import tempfile
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

import anonymizer, audit_log, data_loader, fraud_detection, pii_classifier, rbac  # noqa: E402

results = []


def check(component, description, condition):
    results.append((component, description, bool(condition)))
    print(f"[{'PASS' if condition else 'FAIL'}] {component:<18} {description}")


customers = data_loader.load_customers()
orders = data_loader.load_orders()
anon = data_loader.load_customers_anonymized()
risk = data_loader.load_orders_with_risk()

# 1. Data generation ---------------------------------------------------------
check("Data Generation", "500 customers generated", len(customers) == 500)
check("Data Generation", "5,000 orders generated", len(orders) == 5000)
check("Data Generation", "every order links to a customer",
      orders["customer_id"].isin(customers["customer_id"]).all())

# 2. PII classification ------------------------------------------------------
cls = {r["column"]: r["sensitivity"]
       for r in pii_classifier.classify_dataframe(customers)}
check("PII Classification", "email/full_name/phone/customer_id are DIRECT_IDENTIFIER",
      all(cls[c] == "DIRECT_IDENTIFIER" for c in ["email", "full_name", "phone", "customer_id"]))
check("PII Classification", "card_number is SENSITIVE_ATTRIBUTE",
      cls["card_number"] == "SENSITIVE_ATTRIBUTE")
check("PII Classification", "address/city/country/signup_date are QUASI_IDENTIFIER",
      all(cls[c] == "QUASI_IDENTIFIER" for c in ["address", "city", "country", "signup_date"]))
raw_pn = pii_classifier.classify_column(orders, "product_name", use_allowlist=False)
check("PII Classification", "product_name false positive caught by human-review allowlist",
      raw_pn["sensitivity"] == "DIRECT_IDENTIFIER"
      and pii_classifier.classify_column(orders, "product_name")["sensitivity"] == "NON_SENSITIVE")

# 3. Anonymization -----------------------------------------------------------
check("Anonymization", "direct identifiers are 16-char hashes",
      all(anon[c].str.fullmatch(r"[0-9a-f]{16}").all()
          for c in ["customer_id", "full_name", "email", "phone"]))
check("Anonymization", "hash is deterministic (same input, same hash)",
      anonymizer.hash_value("CUST0001") == anonymizer.hash_value("CUST0001"))
check("Anonymization", "card numbers masked as **** **** **** NNNN",
      anon["card_number"].str.fullmatch(r"\*{4} \*{4} \*{4} \d{4}").all())
check("Anonymization", "addresses redacted", (anon["address"] == "[REDACTED - see city/country]").all())
check("Anonymization", "signup_date generalized to year-month",
      anon["signup_date"].str.fullmatch(r"\d{4}-\d{2}").all())
leaked = set(anon.to_numpy().ravel()) & (
    set(customers["email"]) | set(customers["card_number"]) | set(customers["full_name"])
    | set(customers["phone"]) | set(customers["address"]) | set(customers["customer_id"]))
check("Anonymization", "no raw PII value from customers.csv appears in anonymized file",
      not leaked)
check("Anonymization", "hashed ids still join orders to customers",
      risk["customer_id"].isin(anon["customer_id"]).all())

# 4. RBAC ----------------------------------------------------------------------
perms = {"view_analytics": (True, True), "view_protected_data": (True, True),
         "view_fraud": (True, True), "decrypt_data": (False, True), "view_audit": (False, True)}
check("RBAC", "Analyst/Admin permissions match access-control matrix",
      all(rbac.has_permission("Analyst", p) == a and rbac.has_permission("Admin", p) == b
          for p, (a, b) in perms.items()))
check("RBAC", "valid logins get the right role",
      rbac.authenticate("analyst", "analyst123") == "Analyst"
      and rbac.authenticate("admin", "admin123") == "Admin")
check("RBAC", "wrong password and unknown user are rejected",
      rbac.authenticate("admin", "nope") is None and rbac.authenticate("ghost", "x") is None)

# 5. Decryption ----------------------------------------------------------------
lookup = pd.read_csv(anonymizer.LOOKUP_PATH, dtype=str)
row = lookup.iloc[0]
original = customers[customers["customer_id"].map(anonymizer.hash_value)
                     == row["hashed_customer_id"]].iloc[0]["card_number"]
check("Decryption", "Admin-path decryption returns the original card number",
      anonymizer.decrypt_field(row["hashed_customer_id"]) == original)
check("Decryption", "Analyst lacks decrypt permission", not rbac.has_permission("Analyst", "decrypt_data"))
from cryptography.fernet import Fernet, InvalidToken  # noqa: E402
try:
    Fernet(Fernet.generate_key()).decrypt(row["card_number_encrypted"].encode())
    wrong_key_fails = False
except InvalidToken:
    wrong_key_fails = True
check("Decryption", "a wrong key cannot decrypt the vault", wrong_key_fails)

# 6. Fraud detection -----------------------------------------------------------
metrics = fraud_detection.evaluate(risk)
check("Fraud Detection", "some orders are flagged as anomalies", risk["is_flagged"].sum() > 0)
check("Fraud Detection", "seeded_anomaly is not a model feature",
      "seeded_anomaly" not in fraud_detection.FEATURES)
check("Fraud Detection", f"precision/recall sane (P={metrics['precision']}, R={metrics['recall']})",
      metrics["precision"] > 0.5 and metrics["recall"] > 0.5)

# 7. Audit logging -------------------------------------------------------------
with tempfile.TemporaryDirectory() as tmp:
    db = Path(tmp) / "audit.db"
    audit_log.log_event("admin", "Admin", "DECRYPT_FIELD", "customers.card_number:x",
                        audit_log.SUCCESS, "fraud investigation", db_path=db)
    ev = audit_log.get_events(db_path=db)
    check("Audit Logging", "event stored with user, role, action, status and reason",
          len(ev) == 1 and ev.iloc[0]["username"] == "admin"
          and ev.iloc[0]["action"] == "DECRYPT_FIELD" and ev.iloc[0]["reason"] == "fraud investigation")
    check("Audit Logging", "module exposes no update/delete functions",
          not any(n for n in dir(audit_log) if n.startswith(("update", "delete", "remove"))))

# 8. Dashboard (Streamlit AppTest) ----------------------------------------------
from streamlit.testing.v1 import AppTest  # noqa: E402

with tempfile.TemporaryDirectory() as tmp:
    audit_log.DB_PATH = Path(tmp) / "audit.db"        # keep test events out of the real log

    def login(user, pw):
        at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
        at.text_input[0].input(user)
        at.text_input[1].input(pw)
        at.button[0].click().run()
        return at

    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=60).run()
    check("Dashboard", "login screen shown before authentication",
          at.title[0].value.endswith("Secure E-Commerce Analytics Platform") and len(at.tabs) == 0)

    bad = login("admin", "wrong")
    check("Dashboard", "failed login is rejected and logged",
          len(bad.error) == 1 and (audit_log.get_events()["status"] == "FAILED").any())

    an = login("analyst", "analyst123")
    check("Dashboard", "Analyst sees 3 tabs, no Audit Log tab",
          [t.label for t in an.tabs] == ["Analytics", "Protected Customer Data", "Fraud Detection"])
    check("Dashboard", "Analyst never sees a decrypt button",
          not any("Decrypt" in b.label for b in an.button))

    ad = login("admin", "admin123")
    check("Dashboard", "Admin sees the Audit Log tab",
          "Audit Log" in [t.label for t in ad.tabs])
    decrypt_btn = next(b for b in ad.button if b.label == "Decrypt card number")
    decrypt_btn.click().run()                          # no reason typed
    check("Dashboard", "decrypt without a reason is refused",
          len(ad.warning) == 1 and (audit_log.get_events()["reason"] == "no reason provided").any())
    reason_box = next(t for t in ad.text_input if t.label.startswith("Reason"))
    reason_box.input("test: verifying chargeback").run()
    next(b for b in ad.button if b.label == "Decrypt card number").click().run()
    shown = [c.value for c in ad.code]
    check("Dashboard", "decrypt with a reason shows the card and logs it",
          any(v.isdigit() and len(v) == 16 for v in shown)
          and (audit_log.get_events()["reason"] == "test: verifying chargeback").any())
    audit_log.DB_PATH = ROOT / "logs" / "audit.db"

passed = sum(1 for *_, ok in results if ok)
print(f"\n{passed}/{len(results)} checks passed")
sys.exit(0 if passed == len(results) else 1)
