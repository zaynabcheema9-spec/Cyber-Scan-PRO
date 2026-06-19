import json
import os

DB_PATH = "cache/cve_database.json"


def _load_db():
    if not os.path.exists(DB_PATH):
        return {}
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}


def _save_db(db):
    os.makedirs("cache", exist_ok=True)
    with open(DB_PATH, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=4)


def get_cves(key):
    """
    FAST offline lookup (NO INTERNET)
    """
    db = _load_db()
    return db.get(key.lower(), [])


def store_cves(key, cves):
    """
    Save CVEs into offline database
    """
    db = _load_db()
    db[key.lower()] = cves
    _save_db(db)


def has_cves(key):
    db = _load_db()
    return key.lower() in db