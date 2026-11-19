"""Phase 1 - Synthetic data generation.

Creates 500 fake customers and 5,000 fake orders. No real person's data is used.
Some orders are deliberately made abnormal ("seeded anomalies") so that the fraud
detector in Phase 5 can be evaluated against known ground truth.

Run:  python src/generate_synthetic_data.py
"""
import random
from datetime import date, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

N_CUSTOMERS = 500
N_ORDERS = 5000
ANOMALY_RATE = 0.01          # 1% of orders are seeded anomalies
SEED = 42

FIRST_NAMES = ["Aarav", "Priya", "Rohan", "Ananya", "Vikram", "Neha", "Arjun", "Kavya",
               "Rahul", "Sneha", "Emma", "Liam", "Olivia", "Noah", "Sophia", "James",
               "Isabella", "Lucas", "Mia", "Ethan", "Fatima", "Omar", "Chen", "Mei",
               "Hiroshi", "Yuki", "Carlos", "Sofia", "Hans", "Greta"]
LAST_NAMES = ["Sharma", "Verma", "Gupta", "Singh", "Patel", "Reddy", "Nair", "Kapoor",
              "Mehta", "Iyer", "Smith", "Johnson", "Brown", "Taylor", "Wilson", "Davis",
              "Miller", "Garcia", "Khan", "Ali", "Wang", "Li", "Tanaka", "Sato",
              "Lopez", "Silva", "Muller", "Schmidt", "Rossi", "Dubois"]
STREETS = ["Park Street", "Main Road", "Lake View", "Station Road", "Green Avenue",
           "Market Lane", "Hill Crest", "River Side", "Temple Road", "Garden Street"]
CITIES = {
    "India": ["Delhi", "Mumbai", "Bengaluru", "Faridabad", "Pune", "Chennai"],
    "USA": ["New York", "Austin", "Seattle", "Chicago"],
    "UK": ["London", "Manchester", "Leeds"],
    "Germany": ["Berlin", "Munich", "Hamburg"],
    "Japan": ["Tokyo", "Osaka"],
}
COUNTRY_WEIGHTS = {"India": 0.45, "USA": 0.25, "UK": 0.12, "Germany": 0.10, "Japan": 0.08}
EMAIL_DOMAINS = ["example.com", "mailtest.org", "demo-mail.net"]

# category -> (products, (min_price, max_price))
CATALOG = {
    "Electronics": (["Wireless Mouse", "Bluetooth Speaker", "USB-C Hub", "Power Bank",
                     "Webcam", "Mechanical Keyboard"], (15, 300)),
    "Fashion": (["Running Shoes", "Denim Jacket", "Cotton T-Shirt", "Leather Wallet",
                 "Sunglasses", "Backpack"], (10, 150)),
    "Home & Kitchen": (["Air Fryer", "Coffee Maker", "Cookware Set", "Table Lamp",
                        "Storage Box", "Bedsheet Set"], (8, 200)),
    "Books": (["Python Handbook", "Data Science Guide", "Mystery Novel", "Cookbook",
               "Self-Help Book", "Comic Collection"], (5, 40)),
    "Beauty": (["Face Wash", "Moisturizer", "Perfume", "Hair Dryer", "Lip Balm",
                "Sunscreen"], (4, 80)),
    "Sports": (["Yoga Mat", "Dumbbell Set", "Football", "Cycling Helmet",
                "Water Bottle", "Badminton Racket"], (6, 120)),
}
PAYMENT_METHODS = ["Credit Card", "Debit Card", "UPI", "Net Banking", "Wallet", "PayPal"]


def luhn_check_digit(partial: str) -> str:
    """Return the Luhn check digit so generated card numbers look valid."""
    total = 0
    for i, ch in enumerate(reversed(partial)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def fake_card(rng: random.Random) -> str:
    partial = rng.choice(["4", "5"]) + "".join(str(rng.randint(0, 9)) for _ in range(14))
    return partial + luhn_check_digit(partial)


def fake_phone(rng: random.Random) -> str:
    """Phone numbers in mixed real-world formats (some with extensions)."""
    a, b, c = rng.randint(200, 999), rng.randint(200, 999), rng.randint(1000, 9999)
    ext = rng.randint(10, 999)
    return rng.choice([
        f"+1-{a}-{b}-{c}",
        f"({a}){b}-{c}x{ext}",
        f"{a}-{b}-{c}x{ext}",
        f"001-{a}-{b}-{c}x{ext}",
        f"+91-{rng.randint(70000, 99999)}-{rng.randint(10000, 99999)}",
        f"({a}){b}-{c}",
    ])


def make_customers(rng: random.Random) -> pd.DataFrame:
    countries = list(COUNTRY_WEIGHTS)
    weights = list(COUNTRY_WEIGHTS.values())
    used_emails, rows = set(), []
    for i in range(1, N_CUSTOMERS + 1):
        first, last = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
        email = f"{first}.{last}{rng.randint(1, 999)}@{rng.choice(EMAIL_DOMAINS)}".lower()
        while email in used_emails:
            email = f"{first}.{last}{rng.randint(1, 9999)}@{rng.choice(EMAIL_DOMAINS)}".lower()
        used_emails.add(email)
        country = rng.choices(countries, weights)[0]
        signup = date(2024, 1, 1) + timedelta(days=rng.randint(0, 729))
        rows.append({
            "customer_id": f"CUST{i:04d}",
            "full_name": f"{first} {last}",
            "email": email,
            "phone": fake_phone(rng),
            "address": f"{rng.randint(1, 999)} {rng.choice(STREETS)}, "
                       f"{rng.randint(10, 99)}/{i}",
            "city": rng.choice(CITIES[country]),
            "country": country,
            "card_number": fake_card(rng),
            "signup_date": signup.isoformat(),
        })
    return pd.DataFrame(rows)


def make_orders(customers: pd.DataFrame, rng: random.Random, nprng) -> pd.DataFrame:
    signup = dict(zip(customers["customer_id"], pd.to_datetime(customers["signup_date"])))
    end = pd.Timestamp("2026-06-30")
    n_anomalies = int(N_ORDERS * ANOMALY_RATE)
    anomaly_idx = set(rng.sample(range(N_ORDERS), n_anomalies))
    customer_ids = customers["customer_id"].tolist()
    rows = []
    for i in range(N_ORDERS):
        cid = rng.choice(customer_ids)
        start = max(signup[cid], pd.Timestamp("2025-01-01"))
        order_date = start + timedelta(days=rng.randint(0, max((end - start).days, 0)))
        category = rng.choice(list(CATALOG))
        products, (lo, hi) = CATALOG[category]
        quantity = int(nprng.choice([1, 1, 1, 2, 2, 3, 4, 5]))
        unit_price = round(rng.uniform(lo, hi), 2)
        seeded = 0
        if i in anomaly_idx:
            seeded = 1
            kind = rng.choice(["qty", "price", "both"])
            if kind in ("qty", "both"):
                quantity = rng.randint(20, 50)
            if kind in ("price", "both"):
                unit_price = round(hi * rng.uniform(4, 9), 2)
        rows.append({
            "order_id": f"ORD{i + 1:05d}",
            "customer_id": cid,
            "order_date": order_date.date().isoformat(),
            "category": category,
            "product_name": rng.choice(products),
            "quantity": quantity,
            "unit_price": unit_price,
            "total_amount": round(quantity * unit_price, 2),
            "payment_method": rng.choice(PAYMENT_METHODS),
            "seeded_anomaly": seeded,
        })
    return pd.DataFrame(rows)


def main():
    rng = random.Random(SEED)
    nprng = np.random.default_rng(SEED)
    DATA_DIR.mkdir(exist_ok=True)

    customers = make_customers(rng)
    orders = make_orders(customers, rng, nprng)
    customers.to_csv(DATA_DIR / "customers.csv", index=False)
    orders.to_csv(DATA_DIR / "orders.csv", index=False)

    print("Synthetic data generated")
    print(f"  customers.csv : {len(customers)} rows, {customers.shape[1]} columns")
    print(f"  orders.csv    : {len(orders)} rows, {orders.shape[1]} columns")
    print(f"  seeded anomalies planted in orders: {int(orders['seeded_anomaly'].sum())}")
    print("\nSample customers:")
    print(customers.head(3).to_string(index=False))


if __name__ == "__main__":
    main()
