"""Phase 7 - Streamlit dashboard (entry point).

Login -> role assigned by rbac.py -> the screens each role may see.

    Analyst : Analytics, Protected Customer Data (masked), Fraud Detection
    Admin   : everything above + controlled decryption + Audit Log

Run:  streamlit run app.py
"""
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import anonymizer          # noqa: E402
import audit_log           # noqa: E402
import data_loader         # noqa: E402
import fraud_detection     # noqa: E402
import rbac                # noqa: E402

st.set_page_config(page_title="Secure E-Commerce Analytics Platform",
                   page_icon="🔒", layout="wide")


# ---------------------------------------------------------------- data ------
@st.cache_data
def load_orders_with_customers() -> pd.DataFrame:
    """Orders (hashed customer id) joined with anonymized customers on that hash."""
    orders = data_loader.load_orders_with_risk()
    customers = data_loader.load_customers_anonymized()[["customer_id", "city", "country"]]
    return orders.merge(customers, on="customer_id", how="left")


@st.cache_data
def load_protected_customers() -> pd.DataFrame:
    return data_loader.load_customers_anonymized()


def pipeline_ready() -> bool:
    needed = [anonymizer.ANONYMIZED_PATH, anonymizer.LOOKUP_PATH, anonymizer.KEY_PATH,
              fraud_detection.OUTPUT_PATH]
    return all(p.exists() for p in needed)


# --------------------------------------------------------------- login ------
def render_login():
    st.title("🔒 Secure E-Commerce Analytics Platform")
    st.caption("Please log in to continue.")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log in")
    with st.expander("Demo credentials"):
        st.code("analyst / analyst123   (Analyst)\nadmin   / admin123     (Admin)")

    if submitted:
        role = rbac.authenticate(username, password)
        if role:
            st.session_state.user = {"username": username.strip().lower(), "role": role}
            audit_log.log_event(username.strip().lower(), role, "LOGIN", "dashboard",
                                audit_log.SUCCESS)
            st.rerun()
        else:
            audit_log.log_event(username.strip().lower() or "(blank)", "-", "LOGIN",
                                "dashboard", audit_log.FAILED, "invalid credentials")
            st.error("Invalid username or password.")


# ----------------------------------------------------------- analytics ------
def render_analytics():
    st.subheader("Sales Analytics")
    df = load_orders_with_customers()

    c1, c2 = st.columns(2)
    categories = c1.multiselect("Category", sorted(df["category"].unique()),
                                default=sorted(df["category"].unique()))
    countries = c2.multiselect("Country", sorted(df["country"].dropna().unique()),
                               default=sorted(df["country"].dropna().unique()))
    view = df[df["category"].isin(categories) & df["country"].isin(countries)]

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total revenue", f"{view['total_amount'].sum():,.0f}")
    k2.metric("Orders", f"{len(view):,}")
    k3.metric("Avg order value", f"{view['total_amount'].mean():,.2f}" if len(view) else "-")
    k4.metric("Unique customers", f"{view['customer_id'].nunique():,}")

    left, right = st.columns(2)
    left.markdown("**Revenue by category**")
    left.bar_chart(view.groupby("category")["total_amount"].sum())
    right.markdown("**Revenue by country**")
    right.bar_chart(view.groupby("country")["total_amount"].sum())

    st.markdown("**Monthly revenue**")
    st.line_chart(view.assign(month=view["order_date"].str[:7])
                  .groupby("month")["total_amount"].sum())

    left, right = st.columns(2)
    left.markdown("**Orders by payment method**")
    left.bar_chart(view["payment_method"].value_counts())
    right.markdown("**Top 10 products by revenue**")
    right.dataframe(view.groupby("product_name")["total_amount"].sum()
                    .sort_values(ascending=False).head(10).round(2).reset_index(),
                    hide_index=True)


# ------------------------------------------------- protected customer data --
def render_customer_data(user: dict):
    st.subheader("Protected Customer Data")
    st.caption("Identifiers are hashed, card numbers masked, addresses redacted and "
               "dates generalized to year-month.")
    customers = load_protected_customers()
    st.dataframe(customers, hide_index=True)

    # The decrypt panel is only drawn for roles that hold the permission, and the
    # permission is checked again when the button is pressed.
    if not rbac.has_permission(user["role"], "decrypt_data"):
        return

    st.divider()
    st.markdown("### 🔑 Controlled decryption (Admin only)")
    st.caption("Every decryption needs a reason and is written to the audit log.")
    hashed_id = st.selectbox("Customer (hashed ID)", customers["customer_id"].tolist())
    reason = st.text_input("Reason for decryption (required)")
    if st.button("Decrypt card number"):
        resource = f"customers.card_number:{hashed_id}"
        if not rbac.has_permission(user["role"], "decrypt_data"):
            audit_log.log_event(user["username"], user["role"], "DECRYPT_FIELD", resource,
                                audit_log.DENIED, reason)
            st.error("Permission denied.")
        elif not reason.strip():
            audit_log.log_event(user["username"], user["role"], "DECRYPT_FIELD", resource,
                                audit_log.FAILED, "no reason provided")
            st.warning("Please enter a reason before decrypting.")
        else:
            plaintext = anonymizer.decrypt_field(hashed_id, "card_number")
            audit_log.log_event(user["username"], user["role"], "DECRYPT_FIELD", resource,
                                audit_log.SUCCESS, reason.strip())
            st.success("Decrypted - this action has been logged.")
            st.code(plaintext)


# ------------------------------------------------------ fraud detection -----
def render_fraud():
    st.subheader("Fraud / Anomaly Detection")
    st.caption("Isolation Forest flags unusual orders. An anomaly is a lead for review, "
               "not confirmed fraud.")
    df = data_loader.load_orders_with_risk()
    m = fraud_detection.evaluate(df)

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Orders flagged", int(df["is_flagged"].sum()))
    k2.metric("Seeded anomalies (ground truth)", int(df["seeded_anomaly"].sum()))
    k3.metric("Precision", m["precision"])
    k4.metric("Recall", m["recall"])

    flagged = df[df["is_flagged"] == 1].sort_values("risk_score", ascending=False)
    st.markdown("**Flagged transactions (highest risk first)**")
    cols = ["order_id", "customer_id", "order_date", "category", "product_name",
            "quantity", "unit_price", "total_amount", "payment_method", "risk_score"]
    st.dataframe(flagged[cols], hide_index=True)
    st.markdown("**Flagged orders by category**")
    st.bar_chart(flagged["category"].value_counts())


# ------------------------------------------------------------ audit log -----
def render_audit(user: dict):
    st.subheader("Audit Log")
    if not rbac.has_permission(user["role"], "view_audit"):
        st.error("Permission denied.")
        return

    if st.button("Load / refresh audit log"):
        audit_log.log_event(user["username"], user["role"], "VIEW_AUDIT_LOG", "audit.db",
                            audit_log.SUCCESS)
        st.session_state.audit_loaded = True

    if not st.session_state.get("audit_loaded"):
        st.info("Press the button to load the audit trail (this view is itself logged).")
        return

    events = audit_log.get_events()
    k1, k2, k3 = st.columns(3)
    k1.metric("Total events", len(events))
    k2.metric("Failed / denied", int((events["status"] != audit_log.SUCCESS).sum()))
    k3.metric("Decryptions", int((events["action"] == "DECRYPT_FIELD").sum()))

    f1, f2 = st.columns(2)
    actions = f1.multiselect("Action", sorted(events["action"].unique()))
    statuses = f2.multiselect("Status", sorted(events["status"].unique()))
    if actions:
        events = events[events["action"].isin(actions)]
    if statuses:
        events = events[events["status"].isin(statuses)]
    st.dataframe(events, hide_index=True)


# ----------------------------------------------------------------- main -----
def main():
    user = st.session_state.get("user")
    if not user:
        render_login()
        return

    with st.sidebar:
        st.markdown(f"**User:** {user['username']}")
        st.markdown(f"**Role:** {user['role']}")
        if st.button("Log out"):
            audit_log.log_event(user["username"], user["role"], "LOGOUT", "dashboard",
                                audit_log.SUCCESS)
            st.session_state.clear()
            st.rerun()

    st.title("🔒 Secure E-Commerce Analytics Platform")
    if not pipeline_ready():
        st.error("Pipeline outputs not found. Run steps 2-6 from the README "
                 "(generate data, classify, anonymize, fraud detection) first.")
        return

    tab_names = ["Analytics", "Protected Customer Data", "Fraud Detection"]
    if rbac.has_permission(user["role"], "view_audit"):
        tab_names.append("Audit Log")
    tabs = st.tabs(tab_names)

    with tabs[0]:
        render_analytics()
    with tabs[1]:
        render_customer_data(user)
    with tabs[2]:
        render_fraud()
    if len(tabs) > 3:
        with tabs[3]:
            render_audit(user)


main()
