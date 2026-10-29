from datetime import date, datetime, time as dtime

import pandas as pd
import streamlit as st

import db
import logic

st.set_page_config(page_title="Fraud Transaction Investigation System", layout="wide")

HIGHLIGHT_COLORS = {
    "Critical": "#f4c7c3",
    "High": "#fce0c2",
    "Medium": "#fff2c2",
    "Failed": "#f4c7c3",
}

CSS = """
<style>
.stApp { background: #ffffff; }
section[data-testid="stSidebar"] { background: #f2f2f2; border-right: 1px solid #d0d0d0; }
.block-container { padding-top: 2rem; max-width: 1400px; }
.stApp h1 { font-size: 1.6rem !important; color: #111111 !important; }
.stApp h2, .stApp h3 { font-size: 1.15rem !important; color: #111111 !important; }
.stApp p, .stApp label, .stApp li { color: #111111 !important; }
div[data-testid="stMetric"] { border: 1px solid #d0d0d0; padding: 8px 12px; border-radius: 4px; }
div[data-testid="stDataFrame"] { border: 1px solid #d0d0d0; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def show_metric(label, value, note=""):
    st.metric(label, value)
    if note:
        st.caption(note)


def money(v):
    return f"{v:,.2f}"


def table(rows, columns=None, sev_cols=(), height=None):
    if not rows:
        st.info("No records match.")
        return
    frame = pd.DataFrame(rows)
    if columns:
        frame = frame[[c for c in columns if c in frame.columns]].rename(columns=columns)
    for column in frame.columns:
        if str(frame[column].dtype) == "float64":
            values = frame[column].dropna()
            if (values == values.round()).all():
                frame[column] = frame[column].astype("Int64")

    shown_sev = [columns.get(c, c) if columns else c for c in sev_cols]
    styler = frame.style
    for col in shown_sev:
        if col in frame.columns:
            styler = styler.map(lambda v: f"background-color: {HIGHLIGHT_COLORS.get(v, '')}; color: #111111",
                                subset=[col])
    extra = {}
    if height:
        extra["height"] = min(height, 38 + 35 * len(frame))
    st.dataframe(styler, width="stretch", hide_index=True, **extra)


def flash(kind, message):
    st.session_state.setdefault("flash", []).append((kind, message))


def show_flash():
    for kind, message in st.session_state.pop("flash", []):
        getattr(st, kind)(message)


def run(action, success=None):
    try:
        result = action()
    except logic.ValidationError as exc:
        st.error(str(exc))
        return None
    except db.KeyGenerationError as exc:
        st.error(f"Primary-key generation problem: {exc}")
        return None
    except Exception as exc:
        st.error(f"Operation failed and was rolled back: {exc.__class__.__name__}: {exc}")
        return None
    if success:
        flash("success", success)
    return result


def account_label(a):
    return f"{a['account_number']} - {a['customer_name']} - {a['status']} - bal {money(a['balance'])}"


@st.cache_data(show_spinner=False)
def _cached_verify_schema():
    return db.verify_schema()


try:
    schema_check = _cached_verify_schema()
except db.DatabaseConnectionError as exc:
    _cached_verify_schema.clear()
    st.error("Cannot connect to the database.")
    st.code(str(exc), language="text")
    st.stop()
except Exception as exc:
    _cached_verify_schema.clear()
    st.error(f"Database check failed: {exc.__class__.__name__}: {exc}")
    st.stop()

if not schema_check["ok"]:
    _cached_verify_schema.clear()
    st.error("The connected database is missing columns this application uses:")
    st.code("\n".join(schema_check["missing"]), language="text")
    st.stop()

PAGES = ["Dashboard", "Record a Transaction", "Transactions History", "Fraud Alerts",
         "Investigations & Workload", "Cases & Evidence", "Reference Data"]

with st.sidebar:
    st.markdown("**Fraud Transaction Investigation System**")
    page = st.radio("Navigate", PAGES, label_visibility="collapsed")
    st.caption("")

st.title(page)
show_flash()


def page_dashboard():
    with db.transaction() as cur:
        counts = db.table_counts(cur=cur)
        alert_status = {r["status"]: r["n"] for r in db.alert_status_counts(cur=cur)}
        inv_ongoing = db.count_ongoing_investigations(cur=cur)
        cases_active = db.count_active_cases(cur=cur)
        severity_rows = db.alert_severity_counts(cur=cur)
        status_rows = db.transaction_status_counts(cur=cur)
        recent_alerts_data = db.recent_alerts(8, cur=cur)
        recent_txns_data = db.recent_transactions(8, cur=cur)

    columns = st.columns(6)
    with columns[0]:
        show_metric("Customers", counts["customer"], f"{counts['account']} accounts")
    with columns[1]:
        show_metric("Transactions", f"{counts['transactions']:,}")
    with columns[2]:
        show_metric("Fraud alerts", counts["fraud_alert"], f"{alert_status.get('Open', 0)} open")
    with columns[3]:
        show_metric("Investigations", counts["investigation"], f"{inv_ongoing} ongoing")
    with columns[4]:
        show_metric("Cases", counts["fraud_case"], f"{cases_active} open or escalated")
    with columns[5]:
        show_metric("Evidence items", counts["evidence"], f"{counts['investigator']} investigators")

    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by severity")
        if not severity_rows:
            st.info("No alerts yet.")
        else:
            severity_counts = {row["severity"]: row["n"] for row in severity_rows}
            severity_table = [
                {"Severity": name, "Alerts": severity_counts.get(name, 0)}
                for name in db.SEVERITIES
            ]
            table(severity_table, {"Severity": "Severity", "Alerts": "Alerts"}, sev_cols=["Severity"])
    with right:
        st.subheader("Transactions by status")
        if not status_rows:
            st.info("No transactions yet.")
        else:
            table(status_rows, {"status": "Status", "n": "Transactions"}, sev_cols=["status"])

    st.subheader("Recent alerts")
    table(recent_alerts_data, {"alert_id": "Alert", "alert_date": "Raised", "severity": "Severity",
                                "status": "Status", "fraud_type_name": "Fraud type", "account_number": "Account",
                                "amount": "Amount", "reason": "Reason"}, sev_cols=["severity"])
    st.subheader("Recent transactions")
    table(recent_txns_data, {"transaction_id": "ID", "transaction_date": "Date", "account_number": "Account",
                                      "transaction_type": "Type", "transaction_direction": "Direction",
                                      "amount": "Amount", "status": "Status", "alert_id": "Alert"},
          sev_cols=["status"])


def render_outcome(res):
    box = st.container(border=True)
    with box:
        if res["status"] == "Completed":
            st.success(f"Transaction recorded - ID {res['transaction_id']} - Completed")
        else:
            st.warning(f"Transaction recorded as FAILED - ID {res['transaction_id']}: {res['failure_reason']}")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Transaction ID", res["transaction_id"])
        c2.metric("Amount", money(res["amount"]))
        c3.metric("Balance before", money(res["balance_before"]))
        c4.metric("Balance after", money(res["balance_after"]))
        if res.get("screening_error"):
            st.error(f"Fraud screening failed: {res['screening_error']}. The transaction itself was saved. "
                     f"Use 'Re-run screening' below.")
            if st.button("Re-run screening", key="rescreen"):
                st.session_state["last_result"] = run(lambda: {**res, "screening_error": None,
                                                              "screening": logic.screen_txn(res["transaction_id"])})
                st.rerun()
            return
        scr = res.get("screening")
        if scr is None:
            return
        for w in scr["warnings"]:
            st.caption(w)
        alert = scr["alert"]
        if alert:
            st.markdown(f"**Fraud alert #{alert['alert_id']}** - Severity: {alert['severity']} - "
                        f"{alert['fraud_type_name']} - status {alert['status']}")
            st.write(alert["reason"])
            existing_inv = db.get_investigation_for_alert(alert["alert_id"])
            if existing_inv:
                st.info(f"Investigation #{existing_inv['investigation_id']} assigned to "
                        f"{existing_inv['investigator_name']} ({existing_inv['department_name']}).")
            elif alert["status"] in ("Open", "Under Review"):
                try:
                    pick = logic.preview_assignment(alert["alert_id"])
                    st.caption(f"Next investigator for {alert['department_name']}: {pick['name']} "
                               f"({pick['active_cases']} active cases)")
                except logic.ValidationError as exc:
                    st.warning(str(exc))
                if st.button("Open investigation for this alert", key=f"oi_{alert['alert_id']}"):
                    inv = run(lambda: logic.open_investigation(alert["alert_id"]))
                    if inv:
                        flash("success", f"Investigation #{inv['investigation_id']} opened and assigned to "
                                         f"{inv['investigator_name']} ({inv['department_name']}).")
                        st.rerun()
        else:
            st.success("No fraud rules triggered.")
        evaluated = [{"Rule": r["label"], "Evaluated": "Yes" if r["evaluated"] else "No",
                      "Triggered": "Yes" if r["triggered"] else "No",
                      "Detail": r["reason"] or r["note"]} for r in scr["rules"]]
        with st.expander("Rule-by-rule screening detail"):
            st.dataframe(pd.DataFrame(evaluated), hide_index=True, width="stretch")


def page_record():
    st.session_state.setdefault("txn_token", 0)
    accounts = db.list_accounts()
    if not accounts:
        st.warning("There are no accounts to transact on.")
        return
    types = [t for t in dict.fromkeys(r["transaction_type"] for r in db.distinct_transaction_types())]
    token = st.session_state["txn_token"]
    with st.form(f"txn_form_{token}"):
        c1, c2 = st.columns(2)
        account = c1.selectbox("Account", accounts, format_func=account_label)
        direction = c2.radio("Direction", list(db.TXN_DIRECTIONS), horizontal=True,
                             format_func=lambda d: "Outgoing (Sent)" if d == "Sent" else "Incoming (Received)")
        c3, c4 = st.columns(2)
        choice = c3.selectbox("Transaction type", types + ["Other (type below)"])
        other = c3.text_input("Other type (only used if 'Other' is selected above)")
        amount = c4.number_input("Amount", min_value=0.01, step=0.01, format="%.2f", value=100.00)
        c5, c6 = st.columns(2)
        use_now = c5.checkbox("Use current date & time", value=True)
        d = c5.date_input("Date", value=date.today())
        t = c6.time_input("Time", value=dtime(datetime.now().hour, datetime.now().minute), step=60)
        location = st.text_input("Location")
        description = st.text_input("Description")
        submitted = st.form_submit_button("Process transaction", type="primary")
    if submitted:
        ttype = other if choice.startswith("Other") else choice
        when = None if use_now else datetime.combine(d, t)
        res = run(lambda: logic.do_transaction(account["account_id"], ttype, direction, amount, when,
                                               location, description))
        if res:
            st.session_state["last_result"] = res
            st.session_state["txn_token"] += 1
            st.rerun()
    if st.session_state.get("last_result"):
        st.subheader("Outcome")
        render_outcome(st.session_state["last_result"])


def page_history():
    accounts = db.list_accounts()
    types = list(dict.fromkeys(r["transaction_type"] for r in db.distinct_transaction_types()))
    with st.expander("Filters", expanded=True):
        c1, c2, c3, c4 = st.columns(4)
        acc = c1.selectbox("Account", [None] + accounts, format_func=lambda a: "All" if a is None else account_label(a))
        status = c2.selectbox("Status", [None] + list(db.TXN_STATUSES), format_func=lambda s: s or "All")
        direction = c3.selectbox("Direction", [None] + list(db.TXN_DIRECTIONS), format_func=lambda s: s or "All")
        ttype = c4.selectbox("Type", [None] + types, format_func=lambda s: s or "All")
        c5, c6, c7, c8 = st.columns(4)
        use_dates = c5.checkbox("Filter by date")
        d_from = c5.date_input("From", value=date.today().replace(day=1))
        d_to = c6.date_input("To", value=date.today())
        mn = c7.number_input("Min amount", min_value=0.0, value=0.0, step=100.0)
        mx = c8.number_input("Max amount (0 = none)", min_value=0.0, value=0.0, step=100.0)
        flagged = st.checkbox("Only transactions with a fraud alert")
        limit = st.slider("Max rows", 50, 2000, 500, 50)
    rows = db.list_transactions(
        acc_id=acc["account_id"] if acc else None, status=status, direction=direction, transaction_type=ttype,
        date_from=datetime.combine(d_from, dtime.min) if use_dates else None,
        date_to=datetime.combine(d_to, dtime.max.replace(microsecond=0)) if use_dates else None,
        min_amount=mn or None, max_amount=mx or None, flagged_only=flagged, limit=limit)
    st.caption(f"{len(rows)} transactions shown")
    table(rows, {"transaction_id": "ID", "transaction_date": "Date", "account_number": "Account",
                 "customer_name": "Customer", "transaction_type": "Type", "transaction_direction": "Direction",
                 "amount": "Amount", "status": "Status", "location": "Location", "failure_reason": "Failure reason",
                 "alert_id": "Alert", "alert_severity": "Alert severity"}, sev_cols=["alert_severity"], height=420)
    if rows:
        st.subheader("Transaction detail")
        pick = st.selectbox("Select a transaction", [r["transaction_id"] for r in rows],
                            format_func=lambda i: f"#{i}", key="hist_pick")
        t = db.get_transaction(pick)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"**Transaction #{t['transaction_id']}** - {t['status']}")
            st.write(f"{t['transaction_type']} ({t['transaction_direction']}) of **{money(t['amount'])}** on "
                     f"{t['transaction_date']:%Y-%m-%d %H:%M:%S}")
            st.write(f"Account {t['account_number']} - {t['customer_name']}")
            st.write(f"Location: {t['location'] or '-'}  \nDescription: {t['description'] or '-'}")
            if t["failure_reason"]:
                st.warning(t["failure_reason"])
        with c2:
            alert = db.get_alert_for_transaction(pick)
            if alert:
                st.markdown(f"**Alert #{alert['alert_id']}** - Severity: {alert['severity']} - {alert['status']}")
                st.write(f"{alert['fraud_type_name']} - {alert['reason']}")
                inv = db.get_investigation_for_alert(alert["alert_id"])
                if inv:
                    st.write(f"Investigation #{inv['investigation_id']} ({inv['status']}) - {inv['investigator_name']}")
                    if inv["case_id"]:
                        st.write(f"Case #{inv['case_id']} ({inv['case_status']})")
            else:
                st.info("No fraud alert for this transaction.")


def page_alerts():
    fts = db.list_fraud_types()
    c1, c2, c3, c4 = st.columns(4)
    sev = c1.selectbox("Severity", [None] + list(db.SEVERITIES), format_func=lambda s: s or "All")
    stt = c2.selectbox("Status", [None] + list(db.ALERT_STATUSES), format_func=lambda s: s or "All")
    ft = c3.selectbox("Fraud type", [None] + fts, format_func=lambda f: "All" if f is None else f["fraud_type_name"])
    inv_f = c4.selectbox("Investigation", [None, True, False],
                         format_func=lambda v: {None: "All", True: "Has investigation", False: "None yet"}[v])
    rows = db.list_alerts(severity=sev, status=stt, fraud_type_id=ft["fraud_type_id"] if ft else None,
                          has_investigation=inv_f)
    st.caption(f"{len(rows)} alerts")
    table(rows, {"alert_id": "Alert", "alert_date": "Raised", "severity": "Severity", "status": "Status",
                 "fraud_type_name": "Fraud type", "department_name": "Department", "transaction_id": "Txn",
                 "account_number": "Account", "amount": "Amount", "investigation_id": "Investigation",
                 "reason": "Reason"}, sev_cols=["severity"], height=380)
    if not rows:
        return
    st.subheader("Alert detail and actions")
    pick = st.selectbox("Select an alert", [r["alert_id"] for r in rows], format_func=lambda i: f"#{i}")
    a = db.get_alert(pick)
    st.markdown(f"**Alert #{a['alert_id']}** - Severity: {a['severity']} - {a['status']} - "
                f"{a['fraud_type_name']} ({a['department_name']})")
    st.write(a["reason"])
    inv = db.get_investigation_for_alert(pick)
    c1, c2 = st.columns(2)
    with c1:
        allowed = sorted(logic.ALERT_TRANSITIONS[a["status"]])
        if allowed:
            with st.form(f"alert_status_{pick}"):
                new = st.selectbox("Change status to", allowed)
                if st.form_submit_button("Update status"):
                    if run(lambda: logic.update_alert_status(pick, new), f"Alert #{pick} is now {new}."):
                        st.rerun()
        else:
            st.info(f"Alert is {a['status']} (final).")
    with c2:
        if inv:
            st.info(f"Investigation #{inv['investigation_id']} ({inv['status']}) - assigned to "
                    f"{inv['investigator_name']}, {inv['department_name']}.")
        elif a["status"] in ("Open", "Under Review"):
            try:
                p = logic.preview_assignment(pick)
                st.caption(f"Will be assigned to {p['name']} ({p['department_name']}, {p['active_cases']} active cases)")
            except logic.ValidationError as exc:
                st.warning(str(exc))
            if st.button("Open investigation", key=f"open_inv_{pick}", type="primary"):
                res = run(lambda: logic.open_investigation(pick))
                if res:
                    flash("success", f"Investigation #{res['investigation_id']} opened and assigned to "
                                     f"{res['investigator_name']} ({res['department_name']}).")
                    st.rerun()
        else:
            st.info("This alert is closed out; no investigation can be opened.")


def page_investigations():
    st.subheader("Investigator workload")
    st.caption("Active cases = investigations that are Ongoing, or whose fraud case is Open/Escalated. "
               "New investigations go to the department investigator with the fewest active cases "
               "(ties: lowest investigator ID).")
    wl = db.get_inv_workload()
    table(wl, {"investigator_id": "ID", "name": "Investigator", "department_name": "Department",
               "experience_year": "Experience (yrs)", "total_investigations": "Total",
               "ongoing_investigations": "Ongoing", "open_cases": "Open cases", "active_cases": "Active"})

    st.subheader("Investigations")
    c1, c2 = st.columns(2)
    stt = c1.selectbox("Status", [None] + list(db.INVESTIGATION_STATUSES), format_func=lambda s: s or "All")
    who = c2.selectbox("Investigator", [None] + db.list_investigators(),
                       format_func=lambda i: "All" if i is None else f"{i['name']} ({i['department_name']})")
    rows = db.list_investigations(status=stt, investigator_id=who["investigator_id"] if who else None)
    st.caption(f"{len(rows)} investigations")
    table(rows, {"investigation_id": "ID", "start_date": "Started", "end_date": "Ended", "status": "Status",
                 "investigator_name": "Investigator", "department_name": "Department", "alert_id": "Alert",
                 "alert_severity": "Severity", "case_id": "Case", "case_status": "Case status"},
          sev_cols=["alert_severity"], height=360)
    if not rows:
        return
    pick = st.selectbox("Select an investigation", [r["investigation_id"] for r in rows],
                        format_func=lambda i: f"#{i}")
    inv = db.get_investigation(pick)
    st.markdown(f"**Investigation #{inv['investigation_id']}** - {inv['status']} - alert #{inv['alert_id']} "
                f"({inv['alert_severity']}) - {inv['investigator_name']} ({inv['department_name']})")
    st.write(f"Findings: {inv['findings'] or '-'}")
    c1, c2, c3 = st.columns(3)
    with c1:
        if inv["status"] == "Ongoing":
            with st.form(f"complete_{pick}"):
                findings = st.text_area("Findings", height=100)
                if st.form_submit_button("Complete investigation"):
                    if run(lambda: logic.complete_investigation(pick, findings), f"Investigation #{pick} completed."):
                        st.rerun()
        else:
            st.caption("Completion is only available for Ongoing investigations.")
    with c2:
        if inv["status"] in ("Ongoing", "Completed"):
            if st.button("Close investigation", key=f"close_inv_{pick}"):
                if run(lambda: logic.close_investigation(pick), f"Investigation #{pick} closed."):
                    st.rerun()
        else:
            st.caption("Investigation is closed.")
    with c3:
        if inv["case_id"]:
            st.info(f"Case #{inv['case_id']} ({inv['case_status']})")
        elif inv["status"] != "Closed":
            prio = st.selectbox("Case priority", list(db.CASE_PRIORITIES),
                                index=db.CASE_PRIORITIES.index(logic.CASE_PRIORITY_FROM_SEVERITY[inv["alert_severity"]]),
                                key=f"prio_{pick}")
            if st.button("Open fraud case", key=f"open_case_{pick}", type="primary"):
                case = run(lambda: logic.open_case(pick, prio))
                if case:
                    flash("success", f"Case #{case['case_id']} opened ({case['priority']} priority).")
                    st.rerun()


def page_cases():
    c1, c2, c3 = st.columns(3)
    stt = c1.selectbox("Status", [None] + list(db.CASE_STATUSES), format_func=lambda s: s or "All")
    pri = c2.selectbox("Priority", [None] + list(db.CASE_PRIORITIES), format_func=lambda s: s or "All")
    who = c3.selectbox("Investigator", [None] + db.list_investigators(),
                       format_func=lambda i: "All" if i is None else i["name"])
    rows = db.list_cases(status=stt, priority=pri, investigator_id=who["investigator_id"] if who else None)
    st.caption(f"{len(rows)} cases")
    table(rows, {"case_id": "Case", "case_date": "Opened", "closed_date": "Closed", "priority": "Priority",
                 "status": "Status", "investigation_id": "Investigation", "investigator_name": "Investigator",
                 "alert_severity": "Alert severity", "evidence_count": "Evidence"}, sev_cols=["alert_severity"],
          height=340)
    if not rows:
        return
    pick = st.selectbox("Select a case", [r["case_id"] for r in rows], format_func=lambda i: f"#{i}")
    case = db.get_case(pick)
    st.markdown(f"**Case #{case['case_id']}** - {case['status']} - {case['priority']} priority - investigation "
                f"#{case['investigation_id']} - alert #{case['alert_id']} - transaction #{case['transaction_id']} - "
                f"{case['investigator_name']}")
    a, b = st.columns(2)
    with a:
        if case["status"] == "Open" and st.button("Escalate case", key=f"esc_{pick}"):
            if run(lambda: logic.escalate_case(pick), f"Case #{pick} escalated."):
                st.rerun()
        if case["status"] in ("Open", "Escalated") and st.button("Close case", key=f"cl_{pick}"):
            if run(lambda: logic.close_case(pick), f"Case #{pick} closed."):
                st.rerun()
        if case["status"] == "Closed":
            st.info("Case is closed; no further changes or evidence.")
    with b:
        if case["status"] != "Closed":
            with st.form(f"evidence_{pick}"):
                existing = db.distinct_evidence_types()
                etype = st.selectbox("Evidence type", existing + ["Other (type below)"])
                other = st.text_input("Other type")
                desc = st.text_area("Description", height=80)
                if st.form_submit_button("Attach evidence"):
                    typ = other if etype.startswith("Other") else etype
                    res = run(lambda: logic.attach_evidence(pick, typ, desc))
                    if res:
                        flash("success", f"Evidence #{res['evidence_id']} attached to case #{pick}.")
                        st.rerun()
    st.subheader("Evidence")
    table(db.list_evidence(pick), {"evidence_id": "ID", "evidence_type": "Type", "description": "Description",
                                   "submitted_date": "Submitted"})


def page_reference():
    tabs = st.tabs(["Customers", "Accounts", "Departments", "Fraud types", "Investigators",
                    "Fraud rule configuration", "Database health"])
    depts = db.list_departments()

    with tabs[0]:
        table(db.list_customers(), {"customer_id": "ID", "name": "Name", "email": "Email", "phone": "Phone",
                                    "date_of_birth": "Date of birth", "address": "Address", "created_at": "Created"},
              height=320)
        with st.expander("Add customer"):
            with st.form("add_customer"):
                n, e = st.text_input("Name"), st.text_input("Email")
                dob = st.date_input("Date of birth", value=date(1990, 1, 1), min_value=date(1900, 1, 1))
                ph, ad = st.text_input("Phone"), st.text_input("Address")
                if st.form_submit_button("Create customer"):
                    new = run(lambda: logic.add_customer(n, dob, e, ad, ph))
                    if new:
                        flash("success", f"Customer created with ID {new}.")
                        st.rerun()

    with tabs[1]:
        accounts = db.list_accounts()
        table(accounts, {"account_id": "ID", "account_number": "Number", "customer_name": "Customer",
                         "account_type": "Type", "balance": "Balance", "status": "Status",
                         "opened_date": "Opened"}, height=320)
        with st.expander("Add account"):
            with st.form("add_account"):
                cust = st.selectbox("Customer", db.list_customers(), format_func=lambda c: f"{c['customer_id']} - {c['name']}")
                num, typ = st.text_input("Account number"), st.text_input("Account type (e.g. Savings)")
                bal = st.number_input("Opening balance", min_value=0.0, step=100.0)
                stt = st.selectbox("Status", list(db.ACCOUNT_STATUSES))
                if st.form_submit_button("Create account"):
                    new = run(lambda: logic.add_account(num, typ, cust["customer_id"], date.today(), stt, bal))
                    if new:
                        flash("success", f"Account created with ID {new}.")
                        st.rerun()
        with st.expander("Change account status"):
            with st.form("acc_status"):
                acc = st.selectbox("Account", accounts, format_func=account_label) if accounts else None
                new_s = st.selectbox("New status", list(db.ACCOUNT_STATUSES))
                if st.form_submit_button("Update") and acc:
                    if run(lambda: logic.set_account_status(acc["account_id"], new_s), "Account status updated."):
                        st.rerun()

    with tabs[2]:
        table(depts, {"department_id": "ID", "department_name": "Department", "description": "Description"})
        with st.expander("Add department"):
            with st.form("add_dept"):
                n, d = st.text_input("Name"), st.text_input("Description")
                if st.form_submit_button("Create department"):
                    new = run(lambda: logic.add_department(n, d))
                    if new:
                        flash("success", f"Department created with ID {new}.")
                        st.rerun()

    with tabs[3]:
        fts = db.list_fraud_types()
        table(fts, {"fraud_type_id": "ID", "fraud_type_name": "Name", "severity": "Severity",
                    "department_name": "Department", "is_active": "Active", "description": "Description"},
              sev_cols=["severity"])
        if fts:
            with st.expander("Edit / activate / deactivate"):
                ft = st.selectbox("Fraud type", fts, format_func=lambda f: f"{f['fraud_type_id']} - {f['fraud_type_name']}")
                c1, c2 = st.columns(2)
                label = "Deactivate" if ft["is_active"] else "Activate"
                if c1.button(f"{label} this fraud type"):
                    if run(lambda: logic.set_fraud_type_active(ft["fraud_type_id"], not ft["is_active"]),
                           f"'{ft['fraud_type_name']}' is now {'inactive' if ft['is_active'] else 'active'}."):
                        st.rerun()
                with st.form(f"edit_ft_{ft['fraud_type_id']}"):
                    sev = st.selectbox("Severity", list(db.SEVERITIES), index=db.SEVERITIES.index(ft["severity"]))
                    dept = st.selectbox("Department", depts, index=[d["department_id"] for d in depts].index(ft["department_id"]),
                                        format_func=lambda d: d["department_name"])
                    desc = st.text_input("Description", value=ft["description"] or "")
                    if st.form_submit_button("Save changes"):
                        if run(lambda: logic.edit_fraud_type(ft["fraud_type_id"], sev, dept["department_id"], desc),
                               "Fraud type updated."):
                            st.rerun()
        with st.expander("Add fraud type"):
            with st.form("add_ft"):
                n, d = st.text_input("Name"), st.text_input("Description")
                sev = st.selectbox("Severity", list(db.SEVERITIES))
                dept = st.selectbox("Department", depts, format_func=lambda d: d["department_name"])
                act = st.checkbox("Active", value=True)
                if st.form_submit_button("Create fraud type"):
                    new = run(lambda: logic.add_fraud_type(n, sev, dept["department_id"], d, act))
                    if new:
                        flash("success", f"Fraud type created with ID {new}.")
                        st.rerun()

    with tabs[4]:
        table(db.list_investigators(), {"investigator_id": "ID", "name": "Name", "department_name": "Department",
                                        "experience_year": "Experience (yrs)", "email": "Email", "phone": "Phone"})
        with st.expander("Add investigator"):
            with st.form("add_inv"):
                n, e, p = st.text_input("Name"), st.text_input("Email"), st.text_input("Phone")
                x = st.number_input("Experience (years)", min_value=0, step=1)
                dept = st.selectbox("Department", depts, format_func=lambda d: d["department_name"])
                if st.form_submit_button("Create investigator"):
                    new = run(lambda: logic.add_investigator(n, e, dept["department_id"], p, int(x)))
                    if new:
                        flash("success", f"Investigator created with ID {new}.")
                        st.rerun()

    with tabs[5]:
        render_rule_config(db.list_fraud_types())

    with tabs[6]:
        render_health()


def render_rule_config(fts):
    st.markdown("Items marked **AWAITING CONFIRMATION / PENDING** are not guessed: the affected rule is "
                "skipped (and reported as not evaluated) until you set it.")
    table(logic.config_status(), {"item": "Item", "status": "Status", "detail": "Detail"})
    cfg = logic.get_config()
    st.markdown("**Observed transaction types in the database** (use these to choose withdrawal types)")
    table(db.distinct_transaction_types(), {"transaction_type": "Type", "transaction_direction": "Direction", "n": "Rows"})
    known_types = sorted({r["transaction_type"] for r in db.distinct_transaction_types()})
    with st.form("rule_cfg"):
        mult = st.text_input("High-amount multiplier (x personal average)",
                             value="" if cfg["high_amount_multiplier"] is None else str(cfg["high_amount_multiplier"]),
                             help="Leave blank until confirmed - rule 1 is skipped while blank.")
        wd = st.multiselect("Withdrawal transaction types", known_types,
                            default=[t for t in cfg["withdrawal_types"] if t in known_types])
        sev = st.selectbox("Combined (multiple-rule) severity", list(db.SEVERITIES),
                           index=db.SEVERITIES.index(cfg["combined_severity"]))
        options = [None] + fts
        mapping = {}
        for rule in logic.RULES + ["MULTIPLE"]:
            cur_id = cfg["rule_fraud_type_ids"].get(rule)
            idx = next((i for i, f in enumerate(options) if f and f["fraud_type_id"] == cur_id), 0)
            choice = st.selectbox(f"Fraud type for: {logic.RULE_LABELS[rule]}", options, index=idx,
                                  format_func=lambda f: "- not mapped -" if f is None else
                                  f"#{f['fraud_type_id']} {f['fraud_type_name']} ({f['severity']}, "
                                  f"{'active' if f['is_active'] else 'inactive'})", key=f"map_{rule}")
            mapping[rule] = choice["fraud_type_id"] if choice else None
        if st.form_submit_button("Save rule configuration"):
            if run(lambda: logic.save_config(mult or None, wd, sev, mapping, cfg["auto_open_investigation"]),
                   "Rule configuration saved to rule_config.json."):
                st.rerun()


def render_health():
    st.markdown("**Primary-key generation** (from the PostgreSQL catalog)")
    report = db.check_seqs()
    table(report, {"table": "Table", "pk_column": "PK", "mechanism": "Mechanism", "sequence": "Sequence",
                   "max_id": "Max ID", "next_id": "Next ID", "in_sync": "In sync"})
    bad = [r for r in report if r["mechanism"].startswith("NONE") or not r["in_sync"]]
    if bad:
        st.warning("Some tables cannot generate keys automatically or their generator is behind the data. "
                   "Inserts into those tables will fail with a clear error. A schema/sequence change needs "
                   "your approval - nothing has been changed.")
    st.markdown("**Foreign-key integrity**")
    table(db.check_fks(), {"relationship": "Relationship", "orphans": "Orphan rows", "ok": "OK"})
    st.markdown("**Row counts**")
    st.dataframe(pd.DataFrame([db.table_counts()]), hide_index=True, width="stretch")


PAGE_FUNCS = {
    "Dashboard": page_dashboard, "Record a Transaction": page_record, "Transactions History": page_history,
    "Fraud Alerts": page_alerts, "Investigations & Workload": page_investigations,
    "Cases & Evidence": page_cases, "Reference Data": page_reference,
}
PAGE_FUNCS[page]()
