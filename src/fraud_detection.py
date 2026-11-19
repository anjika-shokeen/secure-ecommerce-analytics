"""Phase 5 - Fraud / anomaly detection with Isolation Forest.

Order Data -> Feature Preparation -> Isolation Forest -> Anomaly Score
           -> Potentially Suspicious Transactions

An anomaly is NOT confirmed fraud - it is an order that looks unusual and deserves
a human look. `seeded_anomaly` (planted ground truth) is never given to the model;
it is only used afterwards to measure precision and recall.

LIMITATION: the model is unsupervised and untuned (see SECURITY_WRITEUP.md).

Run:  python src/fraud_detection.py
"""
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest

from anonymizer import hash_value
from data_loader import load_orders

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_PATH = BASE_DIR / "data" / "orders_with_risk.csv"

FEATURES = ["quantity", "unit_price", "total_amount", "price_vs_category"]
CONTAMINATION = 0.01      # we expect roughly 1% of orders to be unusual


def prepare_features(orders: pd.DataFrame) -> pd.DataFrame:
    """Feature preparation: raw numbers plus 'how pricey is this vs its category'."""
    feats = orders[["quantity", "unit_price", "total_amount"]].copy()
    category_median = orders.groupby("category")["unit_price"].transform("median")
    feats["price_vs_category"] = orders["unit_price"] / category_median
    return feats[FEATURES]


def score_orders(orders: pd.DataFrame) -> pd.DataFrame:
    X = prepare_features(orders)           # seeded_anomaly is NOT used here
    model = IsolationForest(n_estimators=200, contamination=CONTAMINATION, random_state=42)
    model.fit(X)

    result = orders.copy()
    raw = -model.decision_function(X)      # higher = more unusual
    result["anomaly_score"] = raw.round(4)
    # 0-100 risk score, easier for people to read
    result["risk_score"] = ((raw - raw.min()) / (raw.max() - raw.min()) * 100).round(1)
    result["is_flagged"] = (model.predict(X) == -1).astype(int)
    return result


def evaluate(result: pd.DataFrame) -> dict:
    truth, flagged = result["seeded_anomaly"] == 1, result["is_flagged"] == 1
    tp = int((truth & flagged).sum())
    fp = int((~truth & flagged).sum())
    fn = int((truth & ~flagged).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3), "recall": round(recall, 3)}


def main():
    orders = load_orders()
    result = score_orders(orders)
    # Analysts must not see raw customer ids, so hash them in the saved output.
    result["customer_id"] = result["customer_id"].map(hash_value)
    result.to_csv(OUTPUT_PATH, index=False)

    m = evaluate(result)
    print("Fraud / anomaly detection (Isolation Forest)")
    print(f"  orders scored        : {len(result)}")
    print(f"  orders flagged       : {int(result['is_flagged'].sum())}")
    print(f"  seeded anomalies     : {int(result['seeded_anomaly'].sum())}")
    print(f"  true positives       : {m['tp']}")
    print(f"  false positives      : {m['fp']}")
    print(f"  false negatives      : {m['fn']}")
    print(f"  precision            : {m['precision']}")
    print(f"  recall               : {m['recall']}")
    print("\nTop 5 riskiest orders:")
    cols = ["order_id", "category", "quantity", "unit_price", "total_amount", "risk_score"]
    print(result.sort_values("risk_score", ascending=False).head(5)[cols].to_string(index=False))
    print(f"\nSaved {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
