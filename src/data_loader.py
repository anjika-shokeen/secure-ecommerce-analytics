"""Phase 1 - Data loading and first exploration.

Every other module loads data through this file, so file paths and data types
are defined in one place.

Run:  python src/data_loader.py
"""
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

# Everything in the customer table is read as text so that card numbers and
# phone numbers never lose leading digits or get turned into floats.
ORDER_DTYPES = {"order_id": str, "customer_id": str, "order_date": str, "category": str,
                "product_name": str, "payment_method": str}


def load_customers() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "customers.csv", dtype=str)


def load_orders() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "orders.csv", dtype=ORDER_DTYPES)


def load_customers_anonymized() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "customers_anonymized.csv", dtype=str)


def load_orders_with_risk() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "orders_with_risk.csv", dtype=ORDER_DTYPES)


def quick_pii_scan(df: pd.DataFrame) -> list:
    """Very rough name-only heuristic (the proper classifier is Phase 2)."""
    hints = ["name", "email", "phone", "address", "card", "customer_id", "ssn"]
    return [c for c in df.columns if any(h in c.lower() for h in hints)]


def explore():
    customers, orders = load_customers(), load_orders()

    print("=== SHAPE ===")
    print(f"customers: {customers.shape[0]} rows x {customers.shape[1]} columns")
    print(f"orders   : {orders.shape[0]} rows x {orders.shape[1]} columns")

    print("\n=== ORDERS: DATE RANGE & REVENUE ===")
    print(f"dates   : {orders['order_date'].min()}  to  {orders['order_date'].max()}")
    print(f"revenue : {orders['total_amount'].sum():,.2f}")
    print(f"avg order value: {orders['total_amount'].mean():,.2f}")

    print("\n=== MISSING VALUES ===")
    print("customers:", int(customers.isna().sum().sum()), "| orders:", int(orders.isna().sum().sum()))

    print("\n=== REVENUE BY CATEGORY ===")
    print(orders.groupby("category")["total_amount"].sum().sort_values(ascending=False)
          .round(2).to_string())

    print("\n=== QUICK PII HEURISTIC SCAN (name-based only) ===")
    print("customers columns that look sensitive:", quick_pii_scan(customers))
    print("orders columns that look sensitive   :", quick_pii_scan(orders))
    print("(Note: 'product_name' is a false positive here - Phase 2 handles this properly.)")


if __name__ == "__main__":
    explore()
