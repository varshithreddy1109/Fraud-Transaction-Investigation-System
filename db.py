import os
from contextlib import contextmanager
from datetime import datetime
from decimal import Decimal

from dotenv import load_dotenv
import psycopg
import psycopg.conninfo
from psycopg import sql
from psycopg.rows import dict_row

load_dotenv()

CONFIG_HELP = (
    "DATABASE_URL is not set or the connection to Neon failed.\n"
    "Set it in PowerShell using the connection string from the Neon console (Connect):\n"
    '  $env:DATABASE_URL = "<your Neon connection string>"\n'
    "  py -m streamlit run app.py\n"
    "Tip: keep sslmode=require in the string, and URL-encode special characters in the password."
)


class DatabaseConnectionError(RuntimeError):
    pass


class KeyGenerationError(RuntimeError):
    pass


PK = {
    "customer": "customer_id",
    "department": "department_id",
    "fraud_type": "fraud_type_id",
    "investigator": "investigator_id",
    "account": "account_id",
    "transactions": "transaction_id",
    "fraud_alert": "alert_id",
    "investigation": "investigation_id",
    "fraud_case": "case_id",
    "evidence": "evidence_id",
}
TABLES = list(PK)

EXPECTED_COLUMNS = {
    "customer": ["customer_id", "name", "address", "phone", "date_of_birth", "email", "created_at"],
    "department": ["department_id", "department_name", "description"],
    "fraud_type": ["fraud_type_id", "fraud_type_name", "description", "severity", "department_id", "is_active"],
    "investigator": ["investigator_id", "name", "email", "phone", "experience_year", "department_id"],
    "account": ["account_id", "account_number", "account_type", "balance", "opened_date", "status", "customer_id"],
    "transactions": ["transaction_id", "transaction_type", "transaction_direction", "amount", "transaction_date",
                     "status", "location", "description", "failure_reason", "account_id"],
    "fraud_alert": ["alert_id", "reason", "severity", "status", "alert_date", "transaction_id", "fraud_type_id"],
    "investigation": ["investigation_id", "start_date", "end_date", "status", "findings", "alert_id", "investigator_id"],
    "fraud_case": ["case_id", "priority", "case_date", "closed_date", "status", "investigation_id"],
    "evidence": ["evidence_id", "evidence_type", "description", "submitted_date", "case_id"],
}

FOREIGN_KEYS = [
    ("account", "customer_id", "customer", "customer_id"),
    ("transactions", "account_id", "account", "account_id"),
    ("fraud_alert", "transaction_id", "transactions", "transaction_id"),
    ("fraud_alert", "fraud_type_id", "fraud_type", "fraud_type_id"),
    ("fraud_type", "department_id", "department", "department_id"),
    ("investigator", "department_id", "department", "department_id"),
    ("investigation", "alert_id", "fraud_alert", "alert_id"),
    ("investigation", "investigator_id", "investigator", "investigator_id"),
    ("fraud_case", "investigation_id", "investigation", "investigation_id"),
    ("evidence", "case_id", "fraud_case", "case_id"),
]

SEVERITIES = ("Low", "Medium", "High", "Critical")
ALERT_STATUSES = ("Open", "Under Review", "Resolved", "Dismissed")
INVESTIGATION_STATUSES = ("Ongoing", "Completed", "Closed")
CASE_STATUSES = ("Open", "Escalated", "Closed")
CASE_PRIORITIES = ("Low", "Medium", "High")
TXN_STATUSES = ("Completed", "Failed")
TXN_DIRECTIONS = ("Sent", "Received")
ACCOUNT_STATUSES = ("Active", "Inactive", "Frozen", "Closed")


def connect():
    load_dotenv()
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise DatabaseConnectionError(CONFIG_HELP)
    try:
        extra = {} if psycopg.conninfo.conninfo_to_dict(url).get("sslmode") else {"sslmode": "require"}
        return psycopg.connect(url, row_factory=dict_row, connect_timeout=10, prepare_threshold=None, **extra)
    except psycopg.Error as exc:
        first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else exc.__class__.__name__
        raise DatabaseConnectionError(f"Could not connect to Neon PostgreSQL ({first_line}).\n{CONFIG_HELP}") from None
    except Exception as exc:
        raise DatabaseConnectionError(f"DATABASE_URL could not be used ({exc.__class__.__name__}).\n{CONFIG_HELP}") from None


@contextmanager
def transaction(rollback=False):
    conn = connect()
    try:
        with conn.cursor() as cur:
            yield cur
        if rollback:
            conn.rollback()
        else:
            conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def _cur(cur=None):
    if cur is not None:
        yield cur
    else:
        with transaction() as c:
            yield c


def _all(cur, query, params=()):
    cur.execute(query, params)
    return list(cur.fetchall())


def _one(cur, query, params=()):
    cur.execute(query, params)
    return cur.fetchone()


def _insert(cur, table, values):
    pk = PK[table]
    if pk in values:
        raise ValueError(f"Refusing to insert an explicit primary key into {table}.")
    query = sql.SQL("INSERT INTO {t} ({c}) VALUES ({v}) RETURNING {pk}").format(
        t=sql.Identifier(table),
        c=sql.SQL(", ").join(map(sql.Identifier, values)),
        v=sql.SQL(", ").join(sql.Placeholder() * len(values)),
        pk=sql.Identifier(pk),
    )
    try:
        cur.execute(query, list(values.values()))
    except psycopg.errors.NotNullViolation as exc:
        if exc.diag.column_name == pk:
            raise KeyGenerationError(
                f"Table '{table}' has no default for '{pk}'. Check check_seqs()."
            ) from None
        raise
    except psycopg.errors.UniqueViolation as exc:
        if (exc.diag.constraint_name or "").endswith("_pkey"):
            raise KeyGenerationError(
                f"The generator for '{table}.{pk}' created an existing key. Run check_seqs() to sync."
            ) from None
        raise
    return cur.fetchone()[pk]


def verify_schema(cur=None):
    with _cur(cur) as c:
        rows = _all(c, "SELECT table_name, column_name FROM information_schema.columns "
                       "WHERE table_schema = 'public'")
    have = {(r["table_name"].lower(), r["column_name"].lower()) for r in rows}
    missing = [f"{t}.{col}" for t, cols in EXPECTED_COLUMNS.items() for col in cols if (t, col) not in have]
    return {"missing": missing, "ok": len(missing) == 0}


def check_seqs(cur=None):
    out = []
    with _cur(cur) as c:
        meta = _all(c, """
            SELECT cl.relname AS table_name, a.attname AS column_name, a.attidentity AS identity,
                   pg_get_expr(d.adbin, d.adrelid) AS column_default,
                   pg_get_serial_sequence(format('%%I.%%I', n.nspname, cl.relname), a.attname) AS sequence_name
            FROM pg_index i
            JOIN pg_class cl ON cl.oid = i.indrelid
            JOIN pg_namespace n ON n.oid = cl.relnamespace
            JOIN pg_attribute a ON a.attrelid = cl.oid AND a.attnum = ANY (i.indkey)
            LEFT JOIN pg_attrdef d ON d.adrelid = cl.oid AND d.adnum = a.attnum
            WHERE i.indisprimary AND n.nspname = 'public'
        """)
        by_table = {m["table_name"].lower(): m for m in meta}
        for table in TABLES:
            m = by_table.get(table)
            pk = PK[table]
            row = _one(c, sql.SQL("SELECT MAX({pk}) AS m FROM {t}").format(
                pk=sql.Identifier(pk), t=sql.Identifier(table)))
            max_id = row["m"] if row else None
            if not m:
                out.append({
                    "table": table,
                    "pk_column": pk,
                    "mechanism": "NO PRIMARY KEY FOUND",
                    "sequence": None,
                    "max_id": max_id,
                    "next_id": None,
                    "in_sync": False,
                })
                continue
            if m["identity"] == "a":
                mech = "IDENTITY ALWAYS"
            elif m["identity"] == "d":
                mech = "IDENTITY BY DEFAULT"
            elif m["column_default"] and "nextval" in m["column_default"]:
                mech = "SEQUENCE DEFAULT"
            elif m["column_default"]:
                mech = "OTHER DEFAULT"
            else:
                mech = "NONE (plain INT; PostgreSQL cannot generate keys)"
            seq = m["sequence_name"]
            next_id = None
            in_sync = False
            if seq:
                schema, _, name = seq.partition(".")
                s = _one(c, "SELECT last_value, start_value, increment_by FROM pg_sequences "
                            "WHERE schemaname = %s AND sequencename = %s", (schema, name))
                if s:
                    if s["last_value"] is not None:
                        next_id = s["last_value"] + s["increment_by"]
                    else:
                        next_id = s["start_value"]
                    in_sync = (max_id is None) or (next_id > max_id)
            out.append({
                "table": table,
                "pk_column": pk,
                "mechanism": mech,
                "sequence": seq,
                "max_id": max_id,
                "next_id": next_id,
                "in_sync": in_sync,
            })
    return out


def check_fks(cur=None):
    out = []
    with _cur(cur) as c:
        for child, ccol, parent, pcol in FOREIGN_KEYS:
            q = sql.SQL("SELECT COUNT(*) AS n FROM {c} ch LEFT JOIN {p} pa ON pa.{pc} = ch.{cc} "
                        "WHERE ch.{cc} IS NOT NULL AND pa.{pc} IS NULL").format(
                c=sql.Identifier(child), p=sql.Identifier(parent),
                cc=sql.Identifier(ccol), pc=sql.Identifier(pcol))
            n = _one(c, q)["n"]
            out.append({"relationship": f"{child}.{ccol} -> {parent}.{pcol}", "orphans": n, "ok": n == 0})
    return out


def table_counts(cur=None):
    cols = sql.SQL(", ").join(
        sql.SQL("(SELECT COUNT(*) FROM {t}) AS {t}").format(t=sql.Identifier(t))
        for t in TABLES
    )
    with _cur(cur) as c:
        return _one(c, sql.SQL("SELECT ") + cols)


def count_ongoing_investigations(cur=None):
    with _cur(cur) as c:
        return _one(c, "SELECT COUNT(*) AS n FROM investigation WHERE status = 'Ongoing'")["n"]


def count_active_cases(cur=None):
    with _cur(cur) as c:
        return _one(c, "SELECT COUNT(*) AS n FROM fraud_case WHERE status IN ('Open', 'Escalated')")["n"]


def distinct_transaction_types(cur=None):
    with _cur(cur) as c:
        return _all(c, "SELECT transaction_type, transaction_direction, COUNT(*) AS n FROM transactions "
                       "GROUP BY transaction_type, transaction_direction ORDER BY 1, 2")


def list_customers(cur=None):
    with _cur(cur) as c:
        return _all(c, "SELECT customer_id, name, address, phone, date_of_birth, email, created_at "
                       "FROM customer ORDER BY customer_id")


def get_customer(customer_id, cur=None):
    with _cur(cur) as c:
        return _one(c, "SELECT customer_id, name, address, phone, date_of_birth, email, created_at "
                       "FROM customer WHERE customer_id = %s", (customer_id,))


def create_customer(name, date_of_birth, email, address=None, phone=None, cur=None):
    with _cur(cur) as c:
        return _insert(c, "customer", {"name": name, "address": address, "phone": phone,
                                       "date_of_birth": date_of_birth, "email": email})


def list_departments(cur=None):
    with _cur(cur) as c:
        return _all(c, "SELECT department_id, department_name, description FROM department ORDER BY department_id")


def get_department(department_id, cur=None):
    with _cur(cur) as c:
        return _one(c, "SELECT department_id, department_name, description FROM department "
                       "WHERE department_id = %s", (department_id,))


def create_department(department_name, description=None, cur=None):
    with _cur(cur) as c:
        return _insert(c, "department", {"department_name": department_name, "description": description})


def list_investigators(department_id=None, cur=None):
    q = ("SELECT i.investigator_id, i.name, i.email, i.phone, i.experience_year, i.department_id, "
         "d.department_name FROM investigator i JOIN department d ON d.department_id = i.department_id "
         "WHERE (%s::int IS NULL OR i.department_id = %s) ORDER BY i.investigator_id")
    with _cur(cur) as c:
        return _all(c, q, (department_id, department_id))


def create_investigator(name, email, department_id, phone=None, experience_year=None, cur=None):
    with _cur(cur) as c:
        return _insert(c, "investigator", {"name": name, "email": email, "phone": phone,
                                           "experience_year": experience_year, "department_id": department_id})


_FT_COLS = ("ft.fraud_type_id, ft.fraud_type_name, ft.description, ft.severity, ft.department_id, "
            "d.department_name, ft.is_active")


def list_fraud_types(active_only=False, cur=None):
    q = (f"SELECT {_FT_COLS} FROM fraud_type ft JOIN department d ON d.department_id = ft.department_id "
         "WHERE (NOT %s OR ft.is_active) ORDER BY ft.fraud_type_id")
    with _cur(cur) as c:
        return _all(c, q, (active_only,))


def get_fraud_type(fraud_type_id, cur=None):
    q = f"SELECT {_FT_COLS} FROM fraud_type ft JOIN department d ON d.department_id = ft.department_id " \
        "WHERE ft.fraud_type_id = %s"
    with _cur(cur) as c:
        return _one(c, q, (fraud_type_id,))


def create_fraud_type(fraud_type_name, severity, department_id, description=None, is_active=True, cur=None):
    with _cur(cur) as c:
        return _insert(c, "fraud_type", {"fraud_type_name": fraud_type_name, "description": description,
                                         "severity": severity, "department_id": department_id,
                                         "is_active": is_active})


def update_fraud_type(fraud_type_id, severity, department_id, description, cur=None):
    with _cur(cur) as c:
        c.execute("UPDATE fraud_type SET severity = %s, department_id = %s, description = %s "
                  "WHERE fraud_type_id = %s", (severity, department_id, description, fraud_type_id))
        return c.rowcount == 1


def set_fraud_type_active(fraud_type_id, is_active, cur=None):
    with _cur(cur) as c:
        c.execute("UPDATE fraud_type SET is_active = %s WHERE fraud_type_id = %s", (is_active, fraud_type_id))
        return c.rowcount == 1


_ACC_COLS = ("a.account_id, a.account_number, a.account_type, a.balance, a.opened_date, a.status, "
             "a.customer_id, c.name AS customer_name")


def list_accounts(customer_id=None, status=None, cur=None):
    q = (f"SELECT {_ACC_COLS} FROM account a JOIN customer c ON c.customer_id = a.customer_id "
         "WHERE (%s::int IS NULL OR a.customer_id = %s) AND (%s::text IS NULL OR a.status = %s) "
         "ORDER BY a.account_id")
    with _cur(cur) as c:
        return _all(c, q, (customer_id, customer_id, status, status))


def get_account(acc_id, for_update=False, cur=None):
    q = (f"SELECT {_ACC_COLS} FROM account a JOIN customer c ON c.customer_id = a.customer_id "
         "WHERE a.account_id = %s")
    if for_update:
        q += " FOR UPDATE OF a"
    with _cur(cur) as c:
        return _one(c, q, (acc_id,))


def create_account(account_number, account_type, customer_id, opened_date, status="Active",
                   balance=Decimal("0"), cur=None):
    with _cur(cur) as c:
        return _insert(c, "account", {"account_number": account_number, "account_type": account_type,
                                       "balance": balance, "opened_date": opened_date, "status": status,
                                       "customer_id": customer_id})


def apply_balance_change(acc_id, delta, cur=None):
    with _cur(cur) as c:
        row = _one(c, "UPDATE account SET balance = balance + %s WHERE account_id = %s "
                      "AND balance + %s >= 0 RETURNING balance", (delta, acc_id, delta))
        return row["balance"] if row else None


def set_account_status(acc_id, status, cur=None):
    with _cur(cur) as c:
        c.execute("UPDATE account SET status = %s WHERE account_id = %s", (status, acc_id))
        return c.rowcount == 1


_TXN_COLS = ("t.transaction_id, t.transaction_type, t.transaction_direction, t.amount, t.transaction_date, "
             "t.status, t.location, t.description, t.failure_reason, t.account_id")


def insert_transaction(acc_id, transaction_type, transaction_direction, amt, txn_date,
                       status, location=None, description=None, failure_reason=None, cur=None):
    with _cur(cur) as c:
        return _insert(c, "transactions", {
            "transaction_type": transaction_type, "transaction_direction": transaction_direction,
            "amount": amt, "transaction_date": txn_date, "status": status,
            "location": location, "description": description, "failure_reason": failure_reason,
            "account_id": acc_id})


def check_duplicate_txn(acc_id, transaction_type, transaction_direction, amt,
                        txn_date, cur=None):
    q = (f"SELECT {_TXN_COLS} FROM transactions t WHERE t.account_id = %s AND t.transaction_type = %s "
         "AND t.transaction_direction = %s AND t.amount = %s AND t.transaction_date = %s "
         "ORDER BY t.transaction_id LIMIT 1")
    with _cur(cur) as c:
        return _one(c, q, (acc_id, transaction_type, transaction_direction, amt, txn_date))


def get_transaction(txn_id, cur=None):
    q = (f"SELECT {_TXN_COLS}, a.account_number, a.customer_id, c.name AS customer_name "
         "FROM transactions t JOIN account a ON a.account_id = t.account_id "
         "JOIN customer c ON c.customer_id = a.customer_id WHERE t.transaction_id = %s")
    with _cur(cur) as c:
        return _one(c, q, (txn_id,))


def list_transactions(acc_id=None, status=None, direction=None, transaction_type=None,
                      date_from=None, date_to=None,
                      min_amount=None, max_amount=None, flagged_only=False,
                      limit=500, cur=None):
    q = (f"SELECT {_TXN_COLS}, a.account_number, c.name AS customer_name, "
         "fa.alert_id, fa.severity AS alert_severity "
         "FROM transactions t JOIN account a ON a.account_id = t.account_id "
         "JOIN customer c ON c.customer_id = a.customer_id "
         "LEFT JOIN fraud_alert fa ON fa.transaction_id = t.transaction_id "
         "WHERE (%(acc)s::int IS NULL OR t.account_id = %(acc)s) "
         "AND (%(st)s::text IS NULL OR t.status = %(st)s) "
         "AND (%(dir)s::text IS NULL OR t.transaction_direction = %(dir)s) "
         "AND (%(typ)s::text IS NULL OR t.transaction_type = %(typ)s) "
         "AND (%(df)s::timestamp IS NULL OR t.transaction_date >= %(df)s) "
         "AND (%(dt)s::timestamp IS NULL OR t.transaction_date <= %(dt)s) "
         "AND (%(mn)s::numeric IS NULL OR t.amount >= %(mn)s) "
         "AND (%(mx)s::numeric IS NULL OR t.amount <= %(mx)s) "
         "AND (NOT %(fl)s OR fa.alert_id IS NOT NULL) "
         "ORDER BY t.transaction_date DESC, t.transaction_id DESC LIMIT %(lim)s")
    params = dict(acc=acc_id, st=status, dir=direction, typ=transaction_type, df=date_from, dt=date_to,
                  mn=min_amount, mx=max_amount, fl=flagged_only, lim=limit)
    with _cur(cur) as c:
        return _all(c, q, params)


def recent_transactions(limit=8, cur=None):
    return list_transactions(limit=limit, cur=cur)


def count_in_window(acc_id, window_end, window_seconds, status, exclude_txn_id=None,
                    direction=None, types=None, cur=None):
    q = ("SELECT COUNT(*) AS n FROM transactions WHERE account_id = %(acc)s AND status = %(st)s "
         "AND transaction_date >= %(end)s - make_interval(secs => %(secs)s) AND transaction_date <= %(end)s "
         "AND (%(ex)s::int IS NULL OR transaction_id <> %(ex)s) "
         "AND (%(dir)s::text IS NULL OR transaction_direction = %(dir)s) "
         "AND (%(types)s::text[] IS NULL OR transaction_type = ANY(%(types)s::text[]))")
    params = dict(acc=acc_id, st=status, end=window_end, secs=window_seconds, ex=exclude_txn_id,
                  dir=direction, types=list(types) if types is not None else None)
    with _cur(cur) as c:
        return _one(c, q, params)["n"]


def count_matching_in_window(acc_id, window_end, window_seconds, transaction_type, direction, amt,
                             exclude_txn_id, cur=None):
    q = ("SELECT COUNT(*) AS n FROM transactions WHERE account_id = %s AND status = 'Completed' "
         "AND transaction_type = %s AND transaction_direction = %s AND amount = %s "
         "AND transaction_date >= %s - make_interval(secs => %s) AND transaction_date <= %s "
         "AND transaction_id <> %s")
    with _cur(cur) as c:
        return _one(c, q, (acc_id, transaction_type, direction, amt, window_end, window_seconds,
                           window_end, exclude_txn_id))["n"]


def get_user_history(acc_id, up_to, exclude_txn_id, cur=None):
    q = ("SELECT COUNT(*) AS n, AVG(amount) AS avg_amount FROM transactions WHERE account_id = %s "
         "AND status = 'Completed' AND transaction_date <= %s AND transaction_id <> %s")
    with _cur(cur) as c:
        return _one(c, q, (acc_id, up_to, exclude_txn_id))


_ALERT_COLS = ("fa.alert_id, fa.reason, fa.severity, fa.status, fa.alert_date, fa.transaction_id, "
               "fa.fraud_type_id, ft.fraud_type_name, ft.department_id, d.department_name")
_ALERT_FROM = ("FROM fraud_alert fa JOIN fraud_type ft ON ft.fraud_type_id = fa.fraud_type_id "
               "JOIN department d ON d.department_id = ft.department_id")


def insert_alert(txn_id, fraud_type_id, severity, reason, status="Open", cur=None):
    with _cur(cur) as c:
        return _insert(c, "fraud_alert", {"reason": reason, "severity": severity, "status": status,
                                          "transaction_id": txn_id, "fraud_type_id": fraud_type_id})


def get_alert(alert_id, for_update=False, cur=None):
    q = f"SELECT {_ALERT_COLS} {_ALERT_FROM} WHERE fa.alert_id = %s"
    if for_update:
        q += " FOR UPDATE OF fa"
    with _cur(cur) as c:
        return _one(c, q, (alert_id,))


def get_alert_for_transaction(txn_id, cur=None):
    with _cur(cur) as c:
        return _one(c, f"SELECT {_ALERT_COLS} {_ALERT_FROM} WHERE fa.transaction_id = %s", (txn_id,))


def list_alerts(severity=None, status=None, fraud_type_id=None, acc_id=None, has_investigation=None,
                limit=500, cur=None):
    q = (f"SELECT {_ALERT_COLS}, t.account_id, a.account_number, t.amount, t.transaction_date, "
         "inv.investigation_id, inv.investigator_id "
         f"{_ALERT_FROM} JOIN transactions t ON t.transaction_id = fa.transaction_id "
         "JOIN account a ON a.account_id = t.account_id "
         "LEFT JOIN investigation inv ON inv.alert_id = fa.alert_id "
         "WHERE (%(sev)s::text IS NULL OR fa.severity = %(sev)s) "
         "AND (%(st)s::text IS NULL OR fa.status = %(st)s) "
         "AND (%(ft)s::int IS NULL OR fa.fraud_type_id = %(ft)s) "
         "AND (%(acc)s::int IS NULL OR t.account_id = %(acc)s) "
         "AND (%(hi)s::boolean IS NULL OR (inv.investigation_id IS NOT NULL) = %(hi)s) "
         "ORDER BY fa.alert_date DESC, fa.alert_id DESC LIMIT %(lim)s")
    with _cur(cur) as c:
        return _all(c, q, dict(sev=severity, st=status, ft=fraud_type_id, acc=acc_id,
                               hi=has_investigation, lim=limit))


def recent_alerts(limit=8, cur=None):
    return list_alerts(limit=limit, cur=cur)


def set_alert_status(alert_id, status, cur=None):
    with _cur(cur) as c:
        c.execute("UPDATE fraud_alert SET status = %s WHERE alert_id = %s", (status, alert_id))
        return c.rowcount == 1


def alert_severity_counts(cur=None):
    with _cur(cur) as c:
        return _all(c, "SELECT severity, COUNT(*) AS n FROM fraud_alert GROUP BY severity")


def alert_status_counts(cur=None):
    with _cur(cur) as c:
        return _all(c, "SELECT status, COUNT(*) AS n FROM fraud_alert GROUP BY status")


def transaction_status_counts(cur=None):
    with _cur(cur) as c:
        return _all(c, "SELECT status, COUNT(*) AS n FROM transactions GROUP BY status")


_INV_COLS = ("inv.investigation_id, inv.start_date, inv.end_date, inv.status, inv.findings, inv.alert_id, "
             "inv.investigator_id, i.name AS investigator_name, i.department_id, d.department_name, "
             "fa.severity AS alert_severity, fa.status AS alert_status, fa.transaction_id, "
             "fc.case_id, fc.status AS case_status")
_INV_FROM = ("FROM investigation inv JOIN investigator i ON i.investigator_id = inv.investigator_id "
             "JOIN department d ON d.department_id = i.department_id "
             "JOIN fraud_alert fa ON fa.alert_id = inv.alert_id "
             "LEFT JOIN fraud_case fc ON fc.investigation_id = inv.investigation_id")


def insert_investigation(alert_id, investigator_id, status="Ongoing", cur=None):
    with _cur(cur) as c:
        return _insert(c, "investigation", {"alert_id": alert_id, "investigator_id": investigator_id,
                                            "status": status})


def get_investigation(investigation_id, for_update=False, cur=None):
    q = f"SELECT {_INV_COLS} {_INV_FROM} WHERE inv.investigation_id = %s"
    if for_update:
        q += " FOR UPDATE OF inv"
    with _cur(cur) as c:
        return _one(c, q, (investigation_id,))


def get_investigation_for_alert(alert_id, cur=None):
    with _cur(cur) as c:
        return _one(c, f"SELECT {_INV_COLS} {_INV_FROM} WHERE inv.alert_id = %s", (alert_id,))


def list_investigations(status=None, investigator_id=None, limit=500, cur=None):
    q = (f"SELECT {_INV_COLS} {_INV_FROM} WHERE (%(st)s::text IS NULL OR inv.status = %(st)s) "
         "AND (%(iv)s::int IS NULL OR inv.investigator_id = %(iv)s) "
         "ORDER BY inv.start_date DESC, inv.investigation_id DESC LIMIT %(lim)s")
    with _cur(cur) as c:
        return _all(c, q, dict(st=status, iv=investigator_id, lim=limit))


def update_investigation_status(investigation_id, status, findings=None, set_end_date=False, cur=None):
    q = ("UPDATE investigation SET status = %s, findings = COALESCE(%s, findings), "
         "end_date = CASE WHEN %s AND end_date IS NULL THEN GREATEST(now()::timestamp, start_date) ELSE end_date END "
         "WHERE investigation_id = %s")
    with _cur(cur) as c:
        c.execute(q, (status, findings, set_end_date, investigation_id))
        return c.rowcount == 1


def get_inv_workload(department_id=None, cur=None):
    q = ("""
        SELECT i.investigator_id, i.name, i.email, i.experience_year, i.department_id, d.department_name,
               COUNT(inv.investigation_id) AS total_investigations,
               COUNT(*) FILTER (WHERE inv.status = 'Ongoing') AS ongoing_investigations,
               COUNT(*) FILTER (WHERE fc.status IN ('Open', 'Escalated')) AS open_cases,
               COUNT(*) FILTER (WHERE inv.status = 'Ongoing' OR fc.status IN ('Open', 'Escalated')) AS active_cases
        FROM investigator i
        JOIN department d ON d.department_id = i.department_id
        LEFT JOIN investigation inv ON inv.investigator_id = i.investigator_id
        LEFT JOIN fraud_case fc ON fc.investigation_id = inv.investigation_id
        WHERE (%s::int IS NULL OR i.department_id = %s)
        GROUP BY i.investigator_id, i.name, i.email, i.experience_year, i.department_id, d.department_name
        ORDER BY active_cases, i.investigator_id
    """)
    with _cur(cur) as c:
        return _all(c, q, (department_id, department_id))


_CASE_COLS = ("fc.case_id, fc.priority, fc.case_date, fc.closed_date, fc.status, fc.investigation_id, "
              "inv.alert_id, inv.investigator_id, i.name AS investigator_name, inv.status AS investigation_status, "
              "fa.severity AS alert_severity, fa.transaction_id, "
              "(SELECT COUNT(*) FROM evidence e WHERE e.case_id = fc.case_id) AS evidence_count")
_CASE_FROM = ("FROM fraud_case fc JOIN investigation inv ON inv.investigation_id = fc.investigation_id "
              "JOIN investigator i ON i.investigator_id = inv.investigator_id "
              "JOIN fraud_alert fa ON fa.alert_id = inv.alert_id")


def insert_case(investigation_id, priority, status="Open", cur=None):
    with _cur(cur) as c:
        return _insert(c, "fraud_case", {"investigation_id": investigation_id, "priority": priority,
                                         "status": status})


def get_case(case_id, for_update=False, cur=None):
    q = f"SELECT {_CASE_COLS} {_CASE_FROM} WHERE fc.case_id = %s"
    if for_update:
        q += " FOR UPDATE OF fc"
    with _cur(cur) as c:
        return _one(c, q, (case_id,))


def get_case_for_investigation(investigation_id, cur=None):
    with _cur(cur) as c:
        return _one(c, f"SELECT {_CASE_COLS} {_CASE_FROM} WHERE fc.investigation_id = %s", (investigation_id,))


def list_cases(status=None, priority=None, investigator_id=None, limit=500, cur=None):
    q = (f"SELECT {_CASE_COLS} {_CASE_FROM} WHERE (%(st)s::text IS NULL OR fc.status = %(st)s) "
         "AND (%(pr)s::text IS NULL OR fc.priority = %(pr)s) "
         "AND (%(iv)s::int IS NULL OR inv.investigator_id = %(iv)s) "
         "ORDER BY fc.case_date DESC, fc.case_id DESC LIMIT %(lim)s")
    with _cur(cur) as c:
        return _all(c, q, dict(st=status, pr=priority, iv=investigator_id, lim=limit))


def update_case_status(case_id, status, set_closed_date=False, cur=None):
    q = ("UPDATE fraud_case SET status = %s, "
         "closed_date = CASE WHEN %s THEN GREATEST(now()::timestamp, case_date) ELSE closed_date END "
         "WHERE case_id = %s")
    with _cur(cur) as c:
        c.execute(q, (status, set_closed_date, case_id))
        return c.rowcount == 1


def insert_evidence(case_id, evidence_type, description=None, cur=None):
    with _cur(cur) as c:
        return _insert(c, "evidence", {"case_id": case_id, "evidence_type": evidence_type,
                                       "description": description})


def list_evidence(case_id=None, limit=500, cur=None):
    q = ("SELECT e.evidence_id, e.evidence_type, e.description, e.submitted_date, e.case_id "
         "FROM evidence e WHERE (%s::int IS NULL OR e.case_id = %s) "
         "ORDER BY e.submitted_date DESC, e.evidence_id DESC LIMIT %s")
    with _cur(cur) as c:
        return _all(c, q, (case_id, case_id, limit))


def distinct_evidence_types(cur=None):
    with _cur(cur) as c:
        return [r["evidence_type"] for r in _all(c, "SELECT DISTINCT evidence_type FROM evidence ORDER BY 1")]
