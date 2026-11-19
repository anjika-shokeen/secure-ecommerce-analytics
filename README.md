# Secure E-Commerce Analytics Platform — Phase 1

## What this phase does
- Sets up your Python environment
- Generates a realistic synthetic dataset: 500 customers (with fake PII) and
  5,000 orders linking to them
- Loads and explores the data
- Runs a first-pass PII heuristic scan (a preview of Phase 2)

## Step-by-step setup

### 1. Install Python
Download Python 3.11+ from https://www.python.org/downloads/ (check "Add
Python to PATH" during install on Windows). Verify:
```
python --version
```

### 2. Create a virtual environment
From inside the `secure_ecommerce_analytics` folder:

Windows (PowerShell):
```
python -m venv venv
venv\Scripts\activate
```

macOS/Linux:
```
python3 -m venv venv
source venv/bin/activate
```
You'll know it worked because your terminal prompt will show `(venv)` at
the start.

### 3. Install dependencies
```
pip install -r requirements.txt
```

### 4. Generate the dataset
```
python src/generate_synthetic_data.py
```
This creates `data/customers.csv` and `data/orders.csv`. You'll see a
summary printed — e.g. how many "seeded anomalies" were planted (we'll use
these later in Phase 5 to test the fraud detector against ground truth).

### 5. Explore the data
```
python src/data_loader.py
```
This prints:
- Row/column counts for both tables
- Date range and revenue summary
- Missing-value counts
- Revenue by category
- A PII heuristic scan flagging which columns look sensitive and why

## What to look at / understand before moving on
- Open `data/customers.csv` and `data/orders.csv` in a spreadsheet viewer
  and get familiar with the columns.
- Note that `customer_id` is the join key between the two tables.
- Note which columns got flagged in the PII scan (`full_name`, `email`,
  `phone`, `address`, `card_number`) — these are exactly the columns
  Phase 2 will classify formally and Phase 3 will anonymize.
- The `seeded_anomaly` column in `orders.csv` is ground truth we planted on
  purpose (abnormally large quantity/price orders) — don't use it as a
  model input later, only to *evaluate* the fraud detector's accuracy.

## Customizing
- Change `N_CUSTOMERS` / `N_ORDERS` in `generate_synthetic_data.py` for a
  bigger/smaller dataset.
- Want to use the original repo's real sales numbers instead of synthetic
  ones? Drop that CSV into `data/` and adjust `data_loader.py`'s column
  names to match — the rest of the pipeline (Phases 2–8) doesn't care where
  the sales numbers came from, only the PII layer needs to stay synthetic.

## Next: Phase 2
Once you're comfortable with the data, we'll build `src/pii_classifier.py`
— a proper, reusable module that scans any dataframe and classifies columns
by sensitivity level (direct identifier, quasi-identifier, sensitive
attribute, non-sensitive), instead of the quick heuristic used here.

---

# Full Project — Run Everything End to End

Once you've read the individual phase guides (`PHASE2_GUIDE.md`,
`PHASE3_GUIDE.md`, `SECURITY_WRITEUP.md`), here's the complete pipeline in
order. Run these from inside the `secure_ecommerce_analytics` folder, with
your virtual environment activated.

```bash
# 1. Install everything
pip install -r requirements.txt

# 2. Generate synthetic data (500 customers, 5000 orders)
python src/generate_synthetic_data.py

# 3. Explore the raw data
python src/data_loader.py

# 4. Classify every column by sensitivity tier
python src/pii_classifier.py

# 5. Anonymize customer data (hash / encrypt / generalize per tier)
python src/anonymizer.py

# 6. Score every order for fraud/anomaly risk
python src/fraud_detection.py

# 7. (optional) smoke-test the audit log module on its own
python src/audit_log.py

# 8. Launch the full dashboard
streamlit run app.py

# 9. (optional) run the automated checks - one block per row of Table 5.3 in the report
python test_project.py
```

Step 8 opens a browser tab (usually `http://localhost:8501`). Log in with:
```
analyst / analyst123   -> sales dashboard + fraud panel + masked customer data
admin   / admin123     -> all of the above, plus field decryption + audit log
```

## Project Structure
```
secure_ecommerce_analytics/
├── app.py                        # Phase 7 - Streamlit dashboard (entry point)
├── requirements.txt
├── test_project.py               # automated checks (report Table 5.3)
├── README.md                     # you are here
├── PHASE2_GUIDE.md                # PII classification deep-dive
├── PHASE3_GUIDE.md                # anonymization deep-dive
├── SECURITY_WRITEUP.md            # STRIDE threat model + compliance mapping
├── src/
│   ├── generate_synthetic_data.py # Phase 1 - synthetic data generation
│   ├── data_loader.py             # Phase 1 - exploration
│   ├── pii_classifier.py          # Phase 2 - sensitivity classification
│   ├── anonymizer.py              # Phase 3 - hash/encrypt/generalize
│   ├── rbac.py                    # Phase 4 - roles & permissions
│   ├── fraud_detection.py         # Phase 5 - Isolation Forest anomaly detection
│   └── audit_log.py               # Phase 6 - SQLite audit trail
├── data/                          # generated CSVs + encryption key (gitignored)
├── reports/                       # PII classification JSON reports
└── logs/                          # audit.db (gitignored)
```

## What to Submit / Present
1. **The working dashboard** (`streamlit run app.py`) — demo both roles
   live, show the decrypt-with-reason flow, show the audit log updating.
2. **`SECURITY_WRITEUP.md`** as your report appendix — it already has the
   STRIDE table and compliance mapping written out.
3. **The false-positive story from Phase 2** (`product_name` being
   misclassified, then allowlisted) and the **precision/recall numbers
   from Phase 5** (`python src/fraud_detection.py` prints these) — these
   are concrete, specific results that show you evaluated your own system
   rather than just running scripts.
4. Mention the **Known Limitations** section from `SECURITY_WRITEUP.md`
   explicitly in your presentation — evaluators notice when you understand
   a system's edges, not just its happy path.

## Full Reset (if you want to regenerate everything from scratch)
```bash
rm -rf data/*.csv data/*.key reports/*.json logs/*.db
python src/generate_synthetic_data.py
python src/pii_classifier.py
python src/anonymizer.py
python src/fraud_detection.py
```
