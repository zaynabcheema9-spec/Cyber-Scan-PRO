import json
import os
import time

CACHE_DIR = "cache"


def _get_cache_path(key):
    safe_key = key.lower().replace(" ", "_").replace("/", "_")
    return os.path.join(CACHE_DIR, f"{safe_key}.json")


def load_from_cache(key):
    """
    Load CVEs from local cache if available and fresh.
    """
    path = _get_cache_path(key)

    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # optional expiry: 7 days
        if time.time() - data.get("timestamp", 0) > 7 * 24 * 3600:
            return None

        return data.get("cves", [])

    except:
        return None


def save_to_cache(key, cves):
    """
    Save CVEs locally.
    """
    os.makedirs(CACHE_DIR, exist_ok=True)

    path = _get_cache_path(key)

    data = {
        "timestamp": time.time(),
        "cves": cves
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)