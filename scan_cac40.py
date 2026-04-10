#!/usr/bin/env python3
"""Daily CAC40 PQC scan -- runs via GitHub Actions."""

import ssl
import socket
import json
from datetime import datetime, timezone
from pathlib import Path

CAC40_DOMAINS = [
    ("LVMH", "lvmh.com"),
    ("Hermes", "hermes.com"),
    ("L'Oreal", "loreal.com"),
    ("TotalEnergies", "totalenergies.com"),
    ("Sanofi", "sanofi.com"),
    ("Airbus", "airbus.com"),
    ("Schneider Electric", "se.com"),
    ("Air Liquide", "airliquide.com"),
    ("BNP Paribas", "bnpparibas.com"),
    ("Safran", "safran-group.com"),
    ("EssilorLuxottica", "essilorluxottica.com"),
    ("Dassault Systemes", "3ds.com"),
    ("Vinci", "vinci.com"),
    ("AXA", "axa.com"),
    ("Danone", "danone.com"),
    ("Saint-Gobain", "saint-gobain.com"),
    ("Pernod Ricard", "pernod-ricard.com"),
    ("Societe Generale", "societegenerale.com"),
    ("Credit Agricole", "credit-agricole.com"),
    ("Thales", "thalesgroup.com"),
    ("Orange", "orange.com"),
    ("Capgemini", "capgemini.com"),
    ("Michelin", "michelin.com"),
    ("Kering", "kering.com"),
    ("Legrand", "legrand.com"),
    ("Renault", "renault.com"),
    ("Stellantis", "stellantis.com"),
    ("Engie", "engie.com"),
    ("Bouygues", "bouygues.com"),
    ("Teleperformance", "teleperformance.com"),
    ("Publicis", "publicis.com"),
    ("Veolia", "veolia.com"),
    ("Accor", "accor.com"),
    ("Carrefour", "carrefour.com"),
    ("Eurofins", "eurofins.com"),
    ("Vivendi", "vivendi.com"),
    ("ArcelorMittal", "arcelormittal.com"),
    ("Unibail", "urw.com"),
    ("Worldline", "worldline.com"),
    ("STMicroelectronics", "st.com"),
]


PQC_GROUPS = ["X25519MLKEM768", "x25519_mlkem768", "X25519Kyber768Draft00", "mlkem768"]


def find_openssl():
    """Find PQC-capable OpenSSL binary."""
    candidates = []
    try:
        r = subprocess.run(["which", "-a", "openssl"], capture_output=True, timeout=5)
        candidates = [p.strip() for p in r.stdout.decode().strip().split('\n') if p.strip()]
    except:
        pass
    # Also search common locations
    try:
        find_result = subprocess.run(
            ["find", "/usr/bin", "/usr/local/bin", "/opt", "-maxdepth", "3", "-name", "openssl", "-type", "f"],
            capture_output=True, timeout=5
        )
        found = [p.strip() for p in find_result.stdout.decode().strip().split('\n') if p.strip()]
        candidates.extend(found)
    except:
        pass
    candidates += ["/opt/homebrew/Cellar/openssl@3/3.6.1/bin/openssl",
                   "/opt/homebrew/opt/openssl@3/bin/openssl",
                   "/usr/bin/openssl", "/usr/local/bin/openssl", "openssl"]
    seen = set()
    for c in candidates:
        if c in seen:
            continue
        seen.add(c)
        try:
            r = subprocess.run([c, "version"], capture_output=True, timeout=5)
            ver = r.stdout.decode().strip()
            parts = ver.split(' ')[1].split('.') if ' ' in ver else ["0","0"]
            major = int(parts[0]) if parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            if major > 3 or (major == 3 and minor >= 5):
                # Verify PQC actually works
                try:
                    test = subprocess.run(
                        [c, "s_client", "-groups", "X25519MLKEM768", "-connect", "google.com:443"],
                        input=b"", capture_output=True, timeout=8
                    )
                    test_out = test.stdout.decode('utf-8', errors='replace') + test.stderr.decode('utf-8', errors='replace')
                    if "passed invalid" not in test_out and "cannot be set" not in test_out:
                        return c, ver, True
                except:
                    pass
        except:
            continue
    # Fallback
    try:
        r = subprocess.run(["openssl", "version"], capture_output=True, timeout=5)
        return "openssl", r.stdout.decode().strip(), False
    except:
        return "openssl", "unknown", False


OPENSSL_BIN, OPENSSL_VER, PQC_CAPABLE = find_openssl()


def probe_pqc(domain):
    """Probe for PQC hybrid key exchange."""
    if not PQC_CAPABLE:
        return None
    for group in PQC_GROUPS:
        try:
            result = subprocess.run(
                [OPENSSL_BIN, "s_client", "-groups", group,
                 "-connect", f"{domain}:443", "-servername", domain],
                input=b"", capture_output=True, timeout=10
            )
            output = result.stdout.decode('utf-8', errors='replace') + result.stderr.decode('utf-8', errors='replace')
            if "passed invalid" in output or "cannot be set" in output:
                continue
            for line in output.split('\n'):
                if "Negotiated TLS1.3 group:" in line:
                    neg = line.split(":", 1)[-1].strip()
                    if neg and neg != "<NULL>":
                        if any(p in neg.upper() for p in ["KYBER", "MLKEM"]):
                            return neg
            # Also check Server Temp Key
            for line in output.split('\n'):
                if "Server Temp Key:" in line:
                    temp = line.split(":", 1)[-1].strip()
                    if any(p in temp.upper() for p in ["KYBER", "MLKEM"]):
                        return temp
        except:
            continue
    return None


def grade(s):
    if s >= 90: return "A+"
    if s >= 80: return "A"
    if s >= 70: return "B"
    if s >= 60: return "C"
    if s >= 45: return "D"
    if s >= 30: return "E"
    return "F"


def scan_domain(domain):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                tls = ssock.version()
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else ""
                cipher_bits = cipher[2] if cipher else 0

                c = 0
                if tls == "TLSv1.3": c += 25
                elif tls == "TLSv1.2": c += 15
                if "ECDHE" in cipher_name.upper(): c += 25
                elif "DHE" in cipher_name.upper(): c += 10
                if "AES_256" in cipher_name.upper() or "AES256" in cipher_name.upper(): c += 20
                elif "CHACHA20" in cipher_name.upper(): c += 20
                elif "AES_128" in cipher_name.upper(): c += 15
                if "ECDSA" in cipher_name.upper(): c += 20
                else: c += 15
                if "SHA384" in cipher_name.upper() or "SHA256" in cipher_name.upper(): c += 10

                p = 0
                if tls == "TLSv1.3": p += 20
                elif tls == "TLSv1.2": p += 5
                if "ECDHE" in cipher_name.upper(): p += 10
                if "AES_256" in cipher_name.upper() or "CHACHA20" in cipher_name.upper(): p += 20
                elif "AES_128" in cipher_name.upper(): p += 10
                if "ECDSA" in cipher_name.upper(): p += 5
                else: p += 3
                if "SHA384" in cipher_name.upper() or "SHA256" in cipher_name.upper(): p += 5

                # PQC probe
                pqc_group = probe_pqc(domain)
                if pqc_group:
                    p += 40

                result = {
                    "tls": tls, "cipher": cipher_name, "bits": cipher_bits,
                    "classical_score": min(100, c), "pqc_score": min(100, p),
                    "classical_grade": grade(min(100, c)), "pqc_grade": grade(min(100, p)),
                }
                if pqc_group:
                    result["pqc_hybrid"] = pqc_group
                return result
    except Exception as e:
        return {"error": str(e)}


def main():
    print(f"CAC40 PQC Scan -- {datetime.now(timezone.utc).isoformat()}")
    print(f"Python SSL: {ssl.OPENSSL_VERSION}")
    print(f"Scanner binary: {OPENSSL_BIN} ({OPENSSL_VER})")
    print(f"PQC capable: {PQC_CAPABLE}")
    print(f"{'='*70}")

    results = []
    for name, domain in CAC40_DOMAINS:
        r = scan_domain(domain)
        if r.get("error"):
            print(f"  FAIL  {name:<25} {domain:<30} {r['error'][:50]}")
            results.append({"name": name, "domain": domain, "error": r["error"]})
        else:
            print(f"  OK    {name:<25} {domain:<30} C:{r['classical_grade']}({r['classical_score']}) P:{r['pqc_grade']}({r['pqc_score']}) {r['tls']} {r['cipher']}")
            results.append({"name": name, "domain": domain, **r})

    # Add metadata
    output = {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "openssl_version": ssl.OPENSSL_VERSION,
        "total": len(CAC40_DOMAINS),
        "successful": len([r for r in results if not r.get("error")]),
        "results": results
    }

    out_file = Path(__file__).parent / "cac40_results.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    successful = [r for r in results if not r.get("error")]
    avg_c = sum(r["classical_score"] for r in successful) / len(successful) if successful else 0
    avg_p = sum(r["pqc_score"] for r in successful) / len(successful) if successful else 0
    pqc_count = sum(1 for r in successful if r["pqc_score"] >= 60)

    print(f"\n{'='*70}")
    print(f"Scanned: {len(successful)}/{len(CAC40_DOMAINS)}")
    print(f"Avg Classical: {avg_c:.0f}/100 | Avg PQC: {avg_p:.0f}/100")
    print(f"PQC-ready (score >= 60): {pqc_count}/{len(successful)}")


if __name__ == "__main__":
    main()
