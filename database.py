import sqlite3

DB_NAME = "scans.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        ip TEXT,
        open_ports TEXT,
        vulnerabilities TEXT,
        risk_score INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def save_scan(target, ip, open_ports, vulnerabilities, risk_score):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scans (target, ip, open_ports, vulnerabilities, risk_score)
    VALUES (?, ?, ?, ?, ?)
    """, (
        target,
        ip,
        ",".join(map(str, open_ports)) if isinstance(open_ports, list) else str(open_ports),
        ",".join(vulnerabilities) if isinstance(vulnerabilities, list) else str(vulnerabilities),
        risk_score
    ))

    conn.commit()
    conn.close()

def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    scan = cursor.fetchone()

    conn.close()
    return scan
def get_all_scans():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans ORDER BY timestamp DESC")
    rows = cursor.fetchall()

    conn.close()
    return rows