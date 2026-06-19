def severity_to_score(severity):
    """
    Convert CVSS severity to numeric score.
    """
    mapping = {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 1,
        "UNKNOWN": 2
    }
    return mapping.get((severity or "UNKNOWN").upper(), 2)


def calculate_port_risk(cves):
    """
    Calculate risk score for a single port.
    """
    if not cves:
        return 0

    total = 0
    for cve in cves:
        total += severity_to_score(cve.get("severity"))

    # Normalize (avoid huge numbers)
    return min(total * 10, 100)


def calculate_host_risk(results):
    """
    Calculate overall host risk score (0–100).
    """

    host_scores = []

    for host in results:
        port_scores = []

        for protocol in host.get("protocols", []):
            for port in protocol.get("ports", []):
                cves = port.get("cves", [])
                port_score = calculate_port_risk(cves)
                port["risk_score"] = port_score
                port_scores.append(port_score)

        # Aggregate host risk
        if port_scores:
            host_risk = sum(port_scores) / len(port_scores)
        else:
            host_risk = 0

        host["risk_score"] = round(host_risk, 2)
        host_scores.append(host_risk)

    return results