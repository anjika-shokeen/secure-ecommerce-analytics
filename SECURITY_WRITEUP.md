# Security Write-Up: Secure E-Commerce Analytics Platform

## 1. System Overview
This platform ingests e-commerce order and customer data, classifies it by
sensitivity, protects it (hashing, encryption, generalization), enforces
role-based access to it, flags anomalous transactions, and logs every
sensitive access — before any of it is shown on a dashboard.

**Data flow:**
```
Raw data (customers.csv, orders.csv)
   -> PII Classifier (Phase 2)          -> classification report
   -> Anonymizer (Phase 3)              -> anonymized table + encrypted lookup + key
   -> Fraud Detector (Phase 5)          -> risk-scored orders
   -> RBAC-gated Dashboard (Phase 4/7)  -> Analyst / Admin views
   -> Audit Log (Phase 6)               -> every access recorded
```

## 2. Threat Model (STRIDE)

| Threat | Description | Where it applies here | Mitigation in this project |
|---|---|---|---|
| **S**poofing | An attacker pretends to be a legitimate user | Dashboard login | Username/password auth via `rbac.py`. *(Limitation: no MFA, no rate-limiting on login attempts — see §4.)* |
| **T**ampering | Data or logs are modified without authorization | Audit log, CSV data files | SQLite audit log with append-only inserts (no UPDATE/DELETE exposed in the app). *(Limitation: a user with filesystem access to `audit.db` could still edit it directly — production would ship logs to a write-once external store.)* |
| **R**epudiation | A user denies having performed an action | Admin decrypting a card number | Every decrypt requires a typed reason and is logged with timestamp + username + reason (`app.py` → `render_customer_data`), so the action is attributable and can't be plausibly denied. |
| **I**nformation Disclosure | Sensitive data is exposed to those without a need to know | Customer PII, card numbers | Classification (Phase 2) + anonymization (Phase 3) ensure only Admins can decrypt, and only with a logged reason. Analysts never see raw PII, by design of the RBAC permission set in `rbac.py`. |
| **D**enial of Service | The system is made unavailable | Dashboard availability | Out of scope for this project (a demo app, not a production service) — noted as a limitation, not solved. |
| **E**levation of Privilege | A lower-privileged user gains higher-privileged access | Analyst gaining Admin's decrypt ability | Permissions are checked server-side (`has_permission()`) before rendering the decrypt UI at all — an Analyst never even sees the decrypt button, and the check happens again before the action executes, not just at page render. |

## 3. Compliance Mapping

| Control implemented | Maps to |
|---|---|
| PII classification (Phase 2) | GDPR Art. 4 (defining personal data) / Art. 30 (records of processing) |
| Pseudonymization via hashing (Phase 3) | GDPR Art. 4(5) — pseudonymization as a defined safeguard |
| Encryption of sensitive fields at rest (Phase 3) | GDPR Art. 32 (security of processing) / PCI-DSS Req. 3 (protect stored cardholder data) |
| Role-based access control (Phase 4) | PCI-DSS Req. 7 (restrict access by business need-to-know) / SOC 2 CC6 |
| Audit logging of all sensitive access (Phase 6) | PCI-DSS Req. 10 (track and monitor all access) / SOC 2 CC7 / GDPR accountability principle (Art. 5(2)) |
| Anomaly/fraud detection (Phase 5) | PCI-DSS Req. 10.6 (review logs/events for anomalies) — analogous principle applied to transaction data |

## 4. Known Limitations (be upfront about these — it shows rigor, not weakness)
- **Demo credentials are hardcoded** in `rbac.py` with a single shared
  password per role. Production would use a real user database, per-user
  salted password hashes (bcrypt/argon2, not plain SHA-256), and MFA.
- **The hashing salt is a hardcoded string** in `anonymizer.py`. Production
  would pull this from a secrets manager (AWS Secrets Manager, Azure Key
  Vault, HashiCorp Vault) and rotate it periodically.
- **No rate limiting or lockout** on failed logins — vulnerable to brute
  force in its current form. A real deployment would add exponential
  backoff or account lockout after N failed attempts.
- **Generalization (k-anonymity-lite) has no enforced guarantee.** We
  reduce precision on quasi-identifiers but don't mathematically verify
  that every combination maps to at least *k* individuals. Tools like ARX
  (open source) do this properly.
- **The fraud model is unsupervised and untuned for production.** A real
  fraud system would combine this with rules engines, would be retrained
  regularly on fresh data, and would route flagged transactions to human
  review rather than acting on them automatically.
- **Audit log is local SQLite, not tamper-evident.** Production would use
  an append-only, centrally shipped log (e.g. to a SIEM) with integrity
  guarantees (hash chaining or a write-once store).
- **No transport security demoed.** This runs on localhost for
  coursework; a real deployment needs HTTPS/TLS everywhere, plus proper
  session management.

## 5. What Makes This "Intermediate," Not a Toy Project
Most student BI dashboards stop at charts. This project treats the
underlying data as something that needs governance *before* visualization:
classification, protection, controlled access, monitoring, and anomaly
detection — the same lifecycle a real data platform team would apply, just
scaled down and with synthetic data for safety. The limitations section
above is deliberately included: knowing exactly where a system's
boundaries are is itself a core cybersecurity skill, and a good evaluator
will notice you called them out yourself rather than overselling the demo.

## 6. Suggested Future Work (good closing slide for a presentation)
- Swap the local SQLite audit log for a real log pipeline (e.g. Python
  logging → Filebeat → ELK stack, or a managed SIEM).
- Add MFA (e.g. TOTP) to the login flow.
- Formalize k-anonymity guarantees using a library like ARX.
- Add a "break glass" emergency-access pathway for Admins, with even
  stricter after-the-fact review requirements.
- Move from Isolation Forest to a hybrid rules + ML approach, closer to
  how real payment processors structure fraud detection.
