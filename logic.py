from datetime import datetime
from decimal import Decimal, InvalidOperation

import db

MIN_HISTORY_FOR_HIGH_AMOUNT = 10
RAPID_MIN_COUNT = 4
RAPID_WINDOW_SECONDS = 60
FAILED_MIN_COUNT = 4
FAILED_WINDOW_SECONDS = 60
WITHDRAWAL_MIN_COUNT = 5
WITHDRAWAL_WINDOW_SECONDS = 600
DUPLICATE_WINDOW_SECONDS = 30
COMBINED_MIN_RULES = 2

HIGH_AMOUNT_MULTIPLIER = Decimal("3.0")
WITHDRAWAL_TYPES = ("ATM Withdrawal", "Bill Payment", "Card Payment", "Cash Deposit",
                    "IMPS", "NEFT", "Net Banking", "Online Payment", "RTGS", "UPI")
COMBINED_SEVERITY = "Critical"
RULE_FRAUD_TYPE_IDS = {
    "HIGH_AMOUNT": 1,
    "RAPID": 2,
    "REPEATED_FAILED": 3,
    "SUSPICIOUS_WITHDRAWALS": 4,
    "DUPLICATE": 5,
    "MULTIPLE": 6,
}

RULES = ["HIGH_AMOUNT", "RAPID", "REPEATED_FAILED", "SUSPICIOUS_WITHDRAWALS", "DUPLICATE"]
RULE_LABELS = {
    "HIGH_AMOUNT": "Unusually high transaction amount",
    "RAPID": "Rapid transactions",
    "REPEATED_FAILED": "Repeated failed transactions",
    "SUSPICIOUS_WITHDRAWALS": "Suspicious withdrawals",
    "DUPLICATE": "Duplicate transaction",
    "MULTIPLE": "Multiple-rule violation",
}
SEVERITY_RANK = {s: i for i, s in enumerate(db.SEVERITIES)}

CASE_PRIORITY_FROM_SEVERITY = {
    "Low": "Low",
    "Medium": "Medium",
    "High": "High",
    "Critical": "High",
}

ALERT_TRANSITIONS = {
    "Open": {"Under Review", "Resolved", "Dismissed"},
    "Under Review": {"Resolved", "Dismissed"},
    "Resolved": set(),
    "Dismissed": set(),
}
INVESTIGATION_TRANSITIONS = {
    "Ongoing": {"Completed", "Closed"},
    "Completed": {"Closed"},
    "Closed": set(),
}
CASE_TRANSITIONS = {
    "Open": {"Escalated", "Closed"},
    "Escalated": {"Closed"},
    "Closed": set(),
}


class ValidationError(ValueError):
    pass


def _result(rule, evaluated, triggered=False, reason="", note=""):
    return {
        "rule": rule,
        "label": RULE_LABELS[rule],
        "evaluated": evaluated,
        "triggered": triggered,
        "reason": reason,
        "note": note
    }


def _rule_high_amount(cur, txn):
    if txn["status"] != "Completed":
        return _result("HIGH_AMOUNT", True, note="only Completed transactions are checked")
    hist = db.get_user_history(txn["account_id"], txn["transaction_date"], txn["transaction_id"], cur=cur)
    if hist["n"] < MIN_HISTORY_FOR_HIGH_AMOUNT:
        return _result("HIGH_AMOUNT", True,
                       note=f"only {hist['n']} completed historical transactions (need {MIN_HISTORY_FOR_HIGH_AMOUNT})")
    avg = Decimal(hist["avg_amount"])
    limit = avg * HIGH_AMOUNT_MULTIPLIER
    if txn["amount"] > limit:
        return _result("HIGH_AMOUNT", True, True,
                       f"Amount {txn['amount']:,.2f} exceeds {HIGH_AMOUNT_MULTIPLIER}x the account's average completed amount "
                       f"({avg:,.2f}, {hist['n']} transactions)")
    return _result("HIGH_AMOUNT", True, note=f"amount {txn['amount']:,.2f} <= {limit:,.2f}")


def _rule_rapid(cur, txn):
    if txn["status"] != "Completed":
        return _result("RAPID", True, note="current transaction is not Completed")
    prior = db.count_in_window(txn["account_id"], txn["transaction_date"], RAPID_WINDOW_SECONDS, "Completed",
                               exclude_txn_id=txn["transaction_id"], cur=cur)
    total = prior + 1
    if total >= RAPID_MIN_COUNT:
        return _result("RAPID", True, True,
                       f"{total} completed transactions within {RAPID_WINDOW_SECONDS}s (limit {RAPID_MIN_COUNT})")
    return _result("RAPID", True, note=f"{total} in {RAPID_WINDOW_SECONDS}s (< {RAPID_MIN_COUNT})")


def _rule_repeated_failed(cur, txn):
    if txn["status"] != "Failed":
        return _result("REPEATED_FAILED", True, note="current transaction is not Failed")
    prior = db.count_in_window(txn["account_id"], txn["transaction_date"], FAILED_WINDOW_SECONDS, "Failed",
                               exclude_txn_id=txn["transaction_id"], cur=cur)
    total = prior + 1
    if total >= FAILED_MIN_COUNT:
        return _result("REPEATED_FAILED", True, True,
                       f"{total} failed transactions within {FAILED_WINDOW_SECONDS}s (limit {FAILED_MIN_COUNT})")
    return _result("REPEATED_FAILED", True, note=f"{total} failed in {FAILED_WINDOW_SECONDS}s (< {FAILED_MIN_COUNT})")


def _rule_withdrawals(cur, txn):
    if txn["status"] != "Completed" or txn["transaction_direction"] != "Sent" or txn["transaction_type"] not in WITHDRAWAL_TYPES:
        return _result("SUSPICIOUS_WITHDRAWALS", True, note="current transaction is not a completed withdrawal")
    prior = db.count_in_window(txn["account_id"], txn["transaction_date"], WITHDRAWAL_WINDOW_SECONDS, "Completed",
                               exclude_txn_id=txn["transaction_id"], direction="Sent", types=WITHDRAWAL_TYPES, cur=cur)
    total = prior + 1
    if total >= WITHDRAWAL_MIN_COUNT:
        return _result("SUSPICIOUS_WITHDRAWALS", True, True,
                       f"{total} withdrawals within {WITHDRAWAL_WINDOW_SECONDS // 60} minutes "
                       f"(limit {WITHDRAWAL_MIN_COUNT})")
    return _result("SUSPICIOUS_WITHDRAWALS", True,
                   note=f"{total} withdrawals in {WITHDRAWAL_WINDOW_SECONDS // 60} min (< {WITHDRAWAL_MIN_COUNT})")


def _rule_duplicate(cur, txn):
    n = db.count_matching_in_window(txn["account_id"], txn["transaction_date"], DUPLICATE_WINDOW_SECONDS,
                                    txn["transaction_type"], txn["transaction_direction"], txn["amount"],
                                    txn["transaction_id"], cur=cur)
    if n >= 1:
        return _result("DUPLICATE", True, True,
                       f"Same {txn['transaction_type']} ({txn['transaction_direction']}) of {txn['amount']:,.2f} "
                       f"seen {n} time(s) in the previous {DUPLICATE_WINDOW_SECONDS}s")
    return _result("DUPLICATE", True, note=f"no matching transaction in {DUPLICATE_WINDOW_SECONDS}s")


_RULE_FUNCS = {
    "HIGH_AMOUNT": _rule_high_amount,
    "RAPID": _rule_rapid,
    "REPEATED_FAILED": _rule_repeated_failed,
    "SUSPICIOUS_WITHDRAWALS": _rule_withdrawals,
    "DUPLICATE": _rule_duplicate,
}


def _truncate(text, n=255):
    if len(text) <= n:
        return text
    return text[: n - 1] + "…"


def run_fraud_rules(cur, txn, fraud_types=None):
    fts = fraud_types if fraud_types is not None else {ft["fraud_type_id"]: ft for ft in db.list_fraud_types(cur=cur)}
    results = []
    for rule in RULES:
        ft = fts.get(RULE_FRAUD_TYPE_IDS.get(rule))
        if ft is None:
            res = _result(rule, False, note="no fraud type mapped to this rule")
        elif not ft["is_active"]:
            res = _result(rule, False, note=f"fraud type '{ft['fraud_type_name']}' is inactive")
        else:
            res = _RULE_FUNCS[rule](cur, txn)
        res["fraud_type"] = ft
        results.append(res)
    triggered = [r for r in results if r["triggered"]]
    return {"rules": results, "triggered": triggered, "combined": len(triggered) >= COMBINED_MIN_RULES, "fraud_types": fts}


def screen_txn(txn_id, cur=None):
    if cur is None:
        with db.transaction() as c:
            return screen_txn(txn_id, cur=c)

    txn = db.get_transaction(txn_id, cur=cur)
    if txn is None:
        raise ValidationError(f"Transaction {txn_id} does not exist.")
    warnings = []
    existing = db.get_alert_for_transaction(txn_id, cur=cur)
    if existing:
        return {"transaction_id": txn_id, "alert": existing, "created": False, "rules": [],
                "triggered": [], "combined": False, "warnings": ["Transaction was already screened."]}

    ev = run_fraud_rules(cur, txn)
    skipped = [r for r in ev["rules"] if not r["evaluated"]]
    for r in skipped:
        warnings.append(f"{r['label']} not evaluated: {r['note']}.")

    alert = None
    triggered = ev["triggered"]
    if triggered:
        fts = ev["fraud_types"]
        use_combined, ft, severity = False, None, None
        if ev["combined"]:
            cft = fts.get(RULE_FRAUD_TYPE_IDS.get("MULTIPLE"))
            if cft is not None and cft["is_active"]:
                use_combined, ft, severity = True, cft, COMBINED_SEVERITY
            else:
                why = "not mapped" if cft is None else "inactive"
                warnings.append(f"Multiple-rule violation fraud type is {why}; alert recorded under the "
                                 f"highest-severity individual rule instead.")
        if not use_combined:
            best = max(triggered, key=lambda r: (SEVERITY_RANK[r["fraud_type"]["severity"]], -RULES.index(r["rule"])))
            ft, severity = best["fraud_type"], best["fraud_type"]["severity"]
        if use_combined:
            reason = f"Multiple-rule violation ({len(triggered)} rules): " + "; ".join(
                f"{r['label']} - {r['reason']}" for r in triggered)
        elif len(triggered) > 1:
            reason = "; ".join(f"{r['label']} - {r['reason']}" for r in triggered)
        else:
            reason = f"{triggered[0]['label']} - {triggered[0]['reason']}"
        alert_id = db.insert_alert(txn_id, ft["fraud_type_id"], severity, _truncate(reason), cur=cur)
        alert = db.get_alert(alert_id, cur=cur)
    return {"transaction_id": txn_id, "alert": alert, "created": alert is not None,
            "rules": ev["rules"], "triggered": [r["rule"] for r in triggered],
            "combined": ev["combined"], "warnings": warnings}

def _validate_amount(amt):
    try:
        val = Decimal(str(amt))
    except (InvalidOperation, ValueError):
        raise ValidationError("Amount must be a number.") from None
    if not val.is_finite() or val <= 0:
        raise ValidationError("Amount must be greater than zero.")
    if val != val.quantize(Decimal("0.01")):
        raise ValidationError("Amount can have at most 2 decimal places.")
    if val >= Decimal("10") ** 13:
        raise ValidationError("Amount is too large.")
    return val.quantize(Decimal("0.01"))


def do_transaction(acc_id, transaction_type, direction, amt,
                   txn_date=None, location=None,
                   description=None, screen=True):
    ttype = (transaction_type or "").strip()
    if not ttype:
        raise ValidationError("Transaction type is required.")
    if len(ttype) > 30:
        raise ValidationError("Transaction type must be at most 30 characters.")
    if direction not in db.TXN_DIRECTIONS:
        raise ValidationError(f"Direction must be one of {db.TXN_DIRECTIONS}.")
    val = _validate_amount(amt)
    when = (txn_date or datetime.now()).replace(microsecond=0, tzinfo=None)
    loc = (location or "").strip() or None
    desc = (description or "").strip() or None

    with db.transaction() as cur:
        account = db.get_account(acc_id, cur=cur)
        if account is None:
            raise ValidationError(f"Account {acc_id} does not exist.")
        if account["status"] != "Active":
            raise ValidationError(f"Account {account['account_number']} is {account['status']}; "
                                  f"only Active accounts can transact.")
        dup = db.check_duplicate_txn(acc_id, ttype, direction, val, when, cur=cur)
        if dup:
            raise ValidationError(f"This exact transaction was already recorded (ID {dup['transaction_id']}); "
                                  f"not processing it twice.")
        before = account["balance"]
        status, reason, after = "Completed", None, before
        if direction == "Sent":
            new_balance = db.apply_balance_change(acc_id, -val, cur=cur)
            if new_balance is None:
                status, reason = "Failed", f"Insufficient balance (available {before:,.2f}, requested {val:,.2f})"
            else:
                after = new_balance
        else:
            after = db.apply_balance_change(acc_id, val, cur=cur)
            if after is None:
                raise RuntimeError("Credit was refused unexpectedly; transaction rolled back.")
        txn_id = db.insert_transaction(acc_id, ttype, direction, val, when, status, loc,
                                       desc, reason, cur=cur)

    out = {"ok": status == "Completed", "transaction_id": txn_id, "status": status, "failure_reason": reason,
           "account_id": acc_id, "account_number": account["account_number"],
           "balance_before": before, "balance_after": after, "amount": val, "screening": None,
           "screening_error": None}
    if screen:
        try:
            out["screening"] = screen_txn(txn_id)
        except Exception as exc:
            out["screening_error"] = f"{exc.__class__.__name__}: {exc}"
    return out


def select_investigator(cur, department_id):
    pool = db.get_inv_workload(department_id=department_id, cur=cur)
    if not pool:
        dept = db.get_department(department_id, cur=cur)
        name = dept["department_name"] if dept else f"#{department_id}"
        raise ValidationError(f"No investigators exist in department '{name}'; refusing to assign an "
                              f"unrelated investigator.")
    return min(pool, key=lambda r: (r["active_cases"], r["investigator_id"]))


def preview_assignment(alert_id):
    with db.transaction(rollback=True) as cur:
        alert = db.get_alert(alert_id, cur=cur)
        if alert is None:
            raise ValidationError(f"Alert {alert_id} does not exist.")
        return select_investigator(cur, alert["department_id"])


def open_investigation(alert_id):
    with db.transaction() as cur:
        alert = db.get_alert(alert_id, cur=cur)
        if alert is None:
            raise ValidationError(f"Alert {alert_id} does not exist.")
        if alert["status"] in ("Resolved", "Dismissed"):
            raise ValidationError(f"Alert {alert_id} is {alert['status']}; no investigation can be opened.")
        if db.get_investigation_for_alert(alert_id, cur=cur):
            raise ValidationError(f"Alert {alert_id} already has an investigation.")
        investigator = select_investigator(cur, alert["department_id"])
        inv_id = db.insert_investigation(alert_id, investigator["investigator_id"], "Ongoing", cur=cur)
        if alert["status"] == "Open":
            db.set_alert_status(alert_id, "Under Review", cur=cur)
        inv = db.get_investigation(inv_id, cur=cur)
    inv["assigned_active_cases_before"] = investigator["active_cases"]
    return inv


def _check_transition(table, current, new, noun):
    if new not in table.get(current, set()):
        allowed = ", ".join(sorted(table.get(current, set()))) or "none (final state)"
        raise ValidationError(f"{noun} cannot go from '{current}' to '{new}'. Allowed: {allowed}.")


def complete_investigation(investigation_id, findings):
    findings = (findings or "").strip()
    if not findings:
        raise ValidationError("Findings are required to complete an investigation.")
    with db.transaction() as cur:
        inv = db.get_investigation(investigation_id, cur=cur)
        if inv is None:
            raise ValidationError(f"Investigation {investigation_id} does not exist.")
        _check_transition(INVESTIGATION_TRANSITIONS, inv["status"], "Completed", "Investigation")
        db.update_investigation_status(investigation_id, "Completed", findings, set_end_date=True, cur=cur)
        return db.get_investigation(investigation_id, cur=cur)


def close_investigation(investigation_id, findings=None):
    with db.transaction() as cur:
        inv = db.get_investigation(investigation_id, cur=cur)
        if inv is None:
            raise ValidationError(f"Investigation {investigation_id} does not exist.")
        _check_transition(INVESTIGATION_TRANSITIONS, inv["status"], "Closed", "Investigation")
        if inv["case_status"] in ("Open", "Escalated"):
            raise ValidationError(f"Close case {inv['case_id']} first; it is still {inv['case_status']}.")
        db.update_investigation_status(investigation_id, "Closed", (findings or "").strip() or None,
                                       set_end_date=True, cur=cur)
        return db.get_investigation(investigation_id, cur=cur)


def update_alert_status(alert_id, new_status):
    if new_status not in db.ALERT_STATUSES:
        raise ValidationError(f"Unknown alert status '{new_status}'.")
    with db.transaction() as cur:
        alert = db.get_alert(alert_id, cur=cur)
        if alert is None:
            raise ValidationError(f"Alert {alert_id} does not exist.")
        _check_transition(ALERT_TRANSITIONS, alert["status"], new_status, "Alert")
        db.set_alert_status(alert_id, new_status, cur=cur)
        return db.get_alert(alert_id, cur=cur)


def open_case(investigation_id, priority=None):
    with db.transaction() as cur:
        inv = db.get_investigation(investigation_id, cur=cur)
        if inv is None:
            raise ValidationError(f"Investigation {investigation_id} does not exist.")
        if inv["status"] == "Closed":
            raise ValidationError("A case cannot be opened for a Closed investigation.")
        if db.get_case_for_investigation(investigation_id, cur=cur):
            raise ValidationError(f"Investigation {investigation_id} already has a case.")
        prio = priority or CASE_PRIORITY_FROM_SEVERITY[inv["alert_severity"]]
        if prio not in db.CASE_PRIORITIES:
            raise ValidationError(f"Priority must be one of {db.CASE_PRIORITIES}.")
        case_id = db.insert_case(investigation_id, prio, "Open", cur=cur)
        return db.get_case(case_id, cur=cur)


def escalate_case(case_id):
    with db.transaction() as cur:
        case = db.get_case(case_id, cur=cur)
        if case is None:
            raise ValidationError(f"Case {case_id} does not exist.")
        _check_transition(CASE_TRANSITIONS, case["status"], "Escalated", "Case")
        db.update_case_status(case_id, "Escalated", cur=cur)
        return db.get_case(case_id, cur=cur)


def close_case(case_id):
    with db.transaction() as cur:
        case = db.get_case(case_id, cur=cur)
        if case is None:
            raise ValidationError(f"Case {case_id} does not exist.")
        _check_transition(CASE_TRANSITIONS, case["status"], "Closed", "Case")
        db.update_case_status(case_id, "Closed", set_closed_date=True, cur=cur)
        return db.get_case(case_id, cur=cur)


def attach_evidence(case_id, evidence_type, description=None):
    etype = (evidence_type or "").strip()
    if not etype:
        raise ValidationError("Evidence type is required.")
    if len(etype) > 50:
        raise ValidationError("Evidence type must be at most 50 characters.")
    with db.transaction() as cur:
        case = db.get_case(case_id, cur=cur)
        if case is None:
            raise ValidationError(f"Case {case_id} does not exist.")
        if case["status"] == "Closed":
            raise ValidationError(f"Case {case_id} is Closed; evidence cannot be attached.")
        evidence_id = db.insert_evidence(case_id, etype, (description or "").strip() or None, cur=cur)
        return {"evidence_id": evidence_id, "case_id": case_id, "evidence_type": etype}


def _need(value, label):
    val = (value or "").strip() if isinstance(value, str) else value
    if not val:
        raise ValidationError(f"{label} is required.")
    return val


def add_customer(name, date_of_birth, email, address=None, phone=None):
    _need(name, "Name")
    _need(email, "Email")
    if "@" not in email:
        raise ValidationError("Email looks invalid.")
    return db.create_customer(name.strip(), date_of_birth, email.strip(), (address or "").strip() or None,
                               (phone or "").strip() or None)


def add_account(account_number, account_type, customer_id, opened_date, status="Active", balance=0):
    _need(account_number, "Account number")
    _need(account_type, "Account type")
    bal = Decimal(str(balance))
    if bal < 0:
        raise ValidationError("Opening balance cannot be negative.")
    if status not in db.ACCOUNT_STATUSES:
        raise ValidationError("Invalid account status.")
    return db.create_account(account_number.strip(), account_type.strip(), customer_id, opened_date, status, bal)


def add_investigator(name, email, department_id, phone=None, experience_year=None):
    _need(name, "Name")
    _need(email, "Email")
    if experience_year is not None and experience_year < 0:
        raise ValidationError("Experience cannot be negative.")
    return db.create_investigator(name.strip(), email.strip(), department_id, (phone or "").strip() or None,
                                  experience_year)


def add_department(name, description=None):
    _need(name, "Department name")
    return db.create_department(name.strip(), (description or "").strip() or None)


def add_fraud_type(name, severity, department_id, description=None, is_active=True):
    _need(name, "Fraud type name")
    if severity not in db.SEVERITIES:
        raise ValidationError("Invalid severity.")
    return db.create_fraud_type(name.strip(), severity, department_id, (description or "").strip() or None, is_active)


def edit_fraud_type(fraud_type_id, severity, department_id, description=None):
    if severity not in db.SEVERITIES:
        raise ValidationError("Invalid severity.")
    return db.update_fraud_type(fraud_type_id, severity, department_id, (description or "").strip() or None)


def set_fraud_type_active(fraud_type_id, is_active):
    return db.set_fraud_type_active(fraud_type_id, is_active)


def set_account_status(acc_id, status):
    if status not in db.ACCOUNT_STATUSES:
        raise ValidationError("Invalid account status.")
    return db.set_account_status(acc_id, status)
