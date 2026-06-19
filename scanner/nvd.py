import requests
from scanner.cve_db import get_cves, store_cves

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves(product, version=None, limit=3):
    """
    OFFLINE-FIRST CVE ENGINE

    Flow:
    1. Check local DB (FASTEST)
    2. If not found → call NVD API
    3. Store result locally
    4. Return CVEs
    """

    if not product:
        return []

    key = f"{product} {version or ''}".strip()

    # =========================
    # 1. OFFLINE DATABASE CHECK
    # =========================
    cached = get_cves(key)
    if cached:
        print(f"⚡ Offline CVE hit: {product}")
        return cached

    # =========================
    # 2. FALLBACK: NVD API CALL
    # =========================
    params = {
        "keywordSearch": key,
        "resultsPerPage": limit
    }

    headers = {
        "User-Agent": "CyberScan-Pro/1.0"
    }

    try:
        response = requests.get(
            NVD_URL,
            params=params,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            cves = parse_cves(data)

            # Save to offline DB
            store_cves(key, cves)

            return cves

        # Handle API overload gracefully
        if response.status_code in [429, 503]:
            print(f"⚠️ NVD busy ({response.status_code}) → skipping lookup")
            return []

        print(f"⚠️ NVD error {response.status_code}")
        return []

    except requests.exceptions.RequestException as e:
        print(f"⚠️ NVD request failed → {e}")
        return []


# ==================================================
# PARSER FUNCTIONS (SAFE + ROBUST)
# ==================================================

def parse_cves(data):
    """
    Convert NVD response into clean CVE list
    """

    vulnerabilities = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        vulnerabilities.append({
            "id": cve.get("id"),
            "description": get_description(cve),
            "published": cve.get("published"),
            "severity": extract_severity(cve)
        })

    return vulnerabilities


def get_description(cve):
    """
    Safe description extraction
    """
    try:
        return cve.get("descriptions", [{}])[0].get("value", "")
    except:
        return ""


def extract_severity(cve):
    """
    Extract CVSS severity safely
    """

    metrics = cve.get("metrics", {})

    try:
        # CVSS v3.1 (most common)
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]

        # CVSS v3.0 fallback
        if "cvssMetricV30" in metrics:
            return metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]

        # CVSS v2 fallback
        if "cvssMetricV2" in metrics:
            return metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")

    except:
        return "UNKNOWN"

    return "UNKNOWN"