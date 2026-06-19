from scanner.scanner import NetworkScanner
from scanner.parser import parse_results
from scanner.storage import save_results_to_json
from scanner.nvd import fetch_cves
from scanner.risk import calculate_host_risk


def enrich_with_cves(results):
    """
    Attach CVEs to each port.
    """
    for host in results:
        for protocol in host.get("protocols", []):
            for port in protocol.get("ports", []):

                product = port.get("product")
                version = port.get("version")

                if product:
                    print(f"🔍 Checking CVEs for {product} {version or ''} ...")
                    port["cves"] = fetch_cves(product, version)
                else:
                    port["cves"] = []

    return results


def display_results(results):
    """
    Clean terminal output with risk scoring.
    """

    for host in results:
        print("=" * 60)
        print(f"Host   : {host.get('host')}")
        print(f"Status : {host.get('state')}")
        print(f"Risk Score: {host.get('risk_score', 0)}/100")

        for protocol in host.get("protocols", []):
            print(f"\nProtocol: {protocol.get('protocol', '').upper()}")

            for port in protocol.get("ports", []):
                print("-" * 40)
                print(f"Port     : {port.get('port')}")
                print(f"State    : {port.get('state')}")
                print(f"Service  : {port.get('service')}")
                print(f"Product  : {port.get('product')}")
                print(f"Version  : {port.get('version')}")
                print(f"Risk     : {port.get('risk_score', 0)}/100")

                cves = port.get("cves", [])

                if not cves:
                    print("CVEs     : unavailable / none found")
                else:
                    print(f"CVEs     : {len(cves)} found")

                    for cve in cves[:2]:
                        print(f"  - {cve.get('id')} ({cve.get('severity')})")


def main():
    # =========================
    # INPUT
    # =========================
    target = input("Enter IP address or domain: ")

    # =========================
    # SCAN
    # =========================
    scanner = NetworkScanner()
    scan_result = scanner.scan(target)

    # =========================
    # PARSE
    # =========================
    results = parse_results(scan_result)

    # =========================
    # CVE ENRICHMENT
    # =========================
    results = enrich_with_cves(results)

    # =========================
    # RISK SCORING (NEW)
    # =========================
    results = calculate_host_risk(results)

    # =========================
    # DISPLAY
    # =========================
    display_results(results)

    # =========================
    # SAVE JSON
    # =========================
    json_path = save_results_to_json(results, target)
    print(f"\n💾 Results saved to: {json_path}")

    print("\n✅ Scan + CVE + Risk Analysis completed successfully!")


if __name__ == "__main__":
    main()