# Phase 2 — PII / Data Classification (Detailed Guide)

## Goal
Before you can protect sensitive data, you have to know exactly where it
is. This phase builds `src/pii_classifier.py`, a rule-based module that
scans any dataframe and labels each column into one of four tiers:

| Tier | Meaning | Example in our data |
|---|---|---|
| DIRECT_IDENTIFIER | Identifies a person on its own | `full_name`, `email`, `customer_id` |
| SENSITIVE_ATTRIBUTE | Regulated/high-impact if leaked | `card_number` |
| QUASI_IDENTIFIER | Identifies only when combined with others | `city`, `country`, `signup_date` |
| NON_SENSITIVE | Safe to expose | `order_id`, `category`, `total_amount` |

This is the same tiering language used in real data governance frameworks
(and you can cite it directly in your report — it maps cleanly to GDPR's
concept of "personal data" vs "special category data").

## How the classifier decides (3 signals)
1. **Column name** — checked against keyword lists (`DIRECT_ID_KEYWORDS`,
   `QUASI_ID_KEYWORDS`, `SENSITIVE_KEYWORDS`) at the top of the file.
2. **Column content** — a sample of actual values is tested against regex
   patterns for emails, card numbers, and phone numbers. Note the pattern
   check order: dates are tested *before* the loose phone pattern, so a
   `2026-01-05`-style date doesn't get misread as a phone number.
3. **Uniqueness ratio** — if almost every value in a text column is
   different (>95% unique), that's a strong identifier signal even if the
   column name is generic.

Each signal casts a "vote" with a weight; the tier with the highest total
score wins, and the score becomes the confidence.

## Run it
```
python src/pii_classifier.py
```
It prints a full report grouped by tier and reason, and saves machine-
readable versions to `reports/customers_classification.json` and
`reports/orders_classification.json` — Phase 3 (the anonymizer) will read
these JSON files directly instead of re-guessing.

## Important design decision: the allowlist
Early testing showed a real false-positive: `product_name` got flagged as
a direct identifier just because it contains the word "name" — even
though it's a product name, not a person's name. Rather than trying to
write a perfect regex (impossible), we added a small, explicit
**allowlist** (`REVIEWED_NON_PII_COLUMNS`) representing a human reviewer's
sign-off. This is deliberate and worth writing about in your report:

> Automated PII classifiers should never be treated as the final word.
> They're a first-pass triage tool; a human should review and can override
> any label, which is exactly what production DLP (data loss prevention)
> tools do.

You can demo this well in a presentation: show the *before* (false
positive) and *after* (allowlisted) output as evidence you understand the
limitations of automated classification, not just that you can run a
script.

## Low-confidence flagging
Any column with confidence below 0.6 gets an extra note:
`LOW CONFIDENCE - flag for human review before trusting this label`.
This mirrors how real tools triage: they don't just output a label, they
tell you how sure they are, so a human knows where to spend review time.

## Try it yourself (exercises worth doing before moving on)
- Rename a column (e.g. `full_name` → `contact`) and re-run — does it
  still get flagged? (It should, via the email/name content or uniqueness
  signal, not just the name.) If it doesn't, that's a real gap to note.
- Add a new column with fake Aadhaar/SSN-style numbers and extend
  `PATTERNS` with a regex for it.
- Try classifying `orders.csv`'s `payment_method` column — should be
  NON_SENSITIVE. Confirm it is.

## Next: Phase 3
We'll build `src/anonymizer.py`, which reads the classification JSON from
this phase and applies the right protection technique per tier:
hash direct identifiers, generalize quasi-identifiers, and encrypt
sensitive attributes with a recoverable key (for authorized re-identification).
