import streamlit as st
import ssl
import socket
import json
import subprocess
import os
import base64
import time
from datetime import datetime, timezone
from pathlib import Path
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont

# ============================================================
# PQC READINESS SCANNER v4.0
# Built by Amin Hasbini | AI & Cybersecurity Strategy Executive
# ============================================================

st.set_page_config(
    page_title="PQC Readiness Scanner",
    page_icon="🔐",
    layout="wide",
    menu_items={
        'Get help': None,
        'Report a Bug': None,
        'About': 'PQC Readiness Scanner - Built by Amin Hasbini | AI & Cybersecurity Strategy Executive'
    }
)

# --- Language ---
TEXTS = {
    "en": {
        "title": "PQC Readiness Scanner",
        "subtitle": "Dual-score assessment: Classical Security + Post-Quantum Cryptography Readiness",
        "tab_scanner": "🔍 Domain Scanner",
        "tab_hndl": "📊 Harvest Now, Decrypt Later",
        "tab_cloud": "☁️ Cloud Migration",
                "tab_ref": "📋 PQC Reference",
        "tab_faq": "❓ FAQ",
        "enter_domain": "Enter domain to scan",
        "scan_btn": "Scan",
        "scanning": "Scanning",
        "scan_failed": "Scan failed",
        "recently_scanned": "Recently scanned:",
        "detailed_findings": "Detailed Findings",
        "recommendations": "Recommendations",
        "download_report": "📥 Download Full Report (JSON)",
        "share_result": "📤 Share this result",
        "share_linkedin": "Copy for LinkedIn:",
        "about": "About",
        "about_text": """**PQC Readiness Scanner** provides a dual assessment:\n\n**Classical Security** -- How strong is your cryptography today?\n\n**PQC Readiness** -- How prepared are you for quantum computing?\n\nA site can score A in classical security but F in PQC readiness. That gap is the "Harvest Now, Decrypt Later" risk.""",
        "built_by": "Built by",
        "domains_scanned": "domains scanned",
        "classical": "Classical Security",
        "pqc": "PQC Readiness",
    },
    "fr": {
        "title": "Scanner de Maturité PQC",
        "subtitle": "Double évaluation : Sécurité Classique + Maturité Cryptographie Post-Quantique",
        "tab_scanner": "🔍 Scanner de Domaine",
        "tab_hndl": "📊 Récolter Maintenant, Déchiffrer Plus Tard",
        "tab_cloud": "☁️ Migration Cloud",
                "tab_ref": "📋 Référence PQC",
        "tab_faq": "❓ FAQ",
        "enter_domain": "Entrez le domaine à scanner",
        "scan_btn": "Scanner",
        "scanning": "Scan en cours",
        "scan_failed": "Échec du scan",
        "recently_scanned": "Scans récents :",
        "detailed_findings": "Résultats Détaillés",
        "recommendations": "Recommandations",
        "download_report": "📥 Télécharger le Rapport Complet (JSON)",
        "share_result": "📤 Partager ce résultat",
        "share_linkedin": "Copier pour LinkedIn :",
        "about": "À propos",
        "about_text": """**Scanner de Maturité PQC** fournit une double évaluation :\n\n**Sécurité Classique** -- Quelle est la robustesse de votre cryptographie aujourd'hui ?\n\n**Maturité PQC** -- Êtes-vous prêt pour l'informatique quantique ?\n\nUn site peut obtenir un A en sécurité classique mais un F en maturité PQC. Cet écart représente le risque « Récolter Maintenant, Déchiffrer Plus Tard ».""",
        "built_by": "Construit par",
        "domains_scanned": "domaines scannés",
        "classical": "Sécurité Classique",
        "pqc": "Maturité PQC",
    }
}

# --- Persistent scan history ---
SCAN_HISTORY_FILE = Path(__file__).parent / "scan_history.json"

def load_scan_history():
    if SCAN_HISTORY_FILE.exists():
        try:
            with open(SCAN_HISTORY_FILE, "r") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
    return []

def save_scan_history(history):
    history = history[-200:]
    with open(SCAN_HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


# --- Find best OpenSSL binary and check PQC capability ---
@st.cache_resource
def find_openssl_binary():
    """Find the best available OpenSSL binary (prefer 3.5+ for PQC)."""
    # Find ALL openssl binaries on the system
    system_paths = []
    try:
        which_result = subprocess.run(["which", "-a", "openssl"], capture_output=True, timeout=5)
        system_paths = [p.strip() for p in which_result.stdout.decode().strip().split('\n') if p.strip()]
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        pass

    # Also search common locations (with short timeout to avoid blocking startup)
    try:
        find_result = subprocess.run(
            ["find", "/usr/bin", "/usr/local/bin", "/opt", "-maxdepth", "3", "-name", "openssl", "-type", "f"],
            capture_output=True, timeout=5
        )
        found = [p.strip() for p in find_result.stdout.decode().strip().split('\n') if p.strip()]
        system_paths.extend(found)
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        pass

    candidates = system_paths + [
        "/opt/homebrew/Cellar/openssl@3/3.6.1/bin/openssl",  # macOS Homebrew
        "/opt/homebrew/opt/openssl@3/bin/openssl",             # macOS Homebrew alt
        "/usr/local/bin/openssl",                               # Custom install
        "/usr/bin/openssl",                                     # Linux system
        "openssl",                                              # PATH default
    ]
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    candidates = unique
    for binary in candidates:
        try:
            result = subprocess.run(
                [binary, "version"],
                capture_output=True, timeout=5
            )
            version = result.stdout.decode().strip()
            major_minor = version.split(' ')[1] if ' ' in version else "0.0"
            parts = major_minor.split('.')
            major = int(parts[0]) if parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            has_pqc = (major > 3) or (major == 3 and minor >= 5)
            if has_pqc:
                # Verify PQC actually works by testing the groups flag
                try:
                    test = subprocess.run(
                        [binary, "s_client", "-groups", "X25519MLKEM768", "-connect", "google.com:443"],
                        input=b"", capture_output=True, timeout=8
                    )
                    test_out = test.stdout.decode('utf-8', errors='replace') + test.stderr.decode('utf-8', errors='replace')
                    pqc_works = "passed invalid" not in test_out and "cannot be set" not in test_out
                except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
                    pqc_works = False
                return {"binary": binary, "version": version, "pqc_capable": pqc_works, "pqc_verified": pqc_works}
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
            continue

    # Fallback to system openssl
    try:
        result = subprocess.run(["openssl", "version"], capture_output=True, timeout=5)
        version = result.stdout.decode().strip()
        return {"binary": "openssl", "version": version, "pqc_capable": False}
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
        return {"binary": "openssl", "version": "Unknown", "pqc_capable": False}

OPENSSL_INFO = find_openssl_binary()
OPENSSL_BIN = OPENSSL_INFO["binary"]

# PQC groups to test (ordered by preference)
PQC_GROUPS = [
    "x25519_mlkem768",           # OpenSSL 3.5 naming
    "X25519MLKEM768",            # Alternative naming
    "x25519_kyber768",           # Older naming
    "X25519Kyber768Draft00",     # Chrome/draft naming
    "mlkem768",                  # Pure ML-KEM
    "kyber768",                  # Pure Kyber
]




# --- Scan cache with TTL (avoids inconsistent results from CDN edge variability) ---
_scan_cache = {}
_cdn_cache = {}
CACHE_TTL = 3600  # 1 hour

def _cache_get(cache, key):
    if key in cache:
        val, ts = cache[key]
        if time.time() - ts < CACHE_TTL:
            return val
        del cache[key]
    return None

def _cache_set(cache, key, val):
    cache[key] = (val, time.time())

def probe_pqc_support(domain: str) -> dict:
    """Probe a domain for PQC hybrid key exchange support using OpenSSL.
    Tries up to 3 times to account for CDN edge server variability."""

    # Return cached result if available and not expired
    cached = _cache_get(_scan_cache, domain)
    if cached:
        return cached

    pqc_result = {
        "supported": False,
        "group": None,
        "details": None,
        "openssl_pqc_capable": OPENSSL_INFO["pqc_capable"],
        "openssl_version": OPENSSL_INFO["version"],
        "python_ssl_version": ssl.OPENSSL_VERSION,
    }

    # Check if Python's SSL library version supports PQC
    py_ssl_ver = ssl.OPENSSL_VERSION
    py_parts = py_ssl_ver.split(' ')
    py_version = py_parts[1] if len(py_parts) > 1 else "0.0"
    py_major = int(py_version.split('.')[0]) if py_version.split('.')[0].isdigit() else 0
    py_minor = int(py_version.split('.')[1]) if len(py_version.split('.')) > 1 and py_version.split('.')[1].isdigit() else 0
    python_has_pqc = (py_major > 3) or (py_major == 3 and py_minor >= 5)

    if not OPENSSL_INFO["pqc_capable"] and not python_has_pqc:
        pqc_result["details"] = f"Neither OpenSSL binary ({OPENSSL_INFO['version']}) nor Python SSL ({py_ssl_ver}) supports PQC"
        _cache_set(_scan_cache, domain, pqc_result)
        return pqc_result

    # Try up to 3 times to account for CDN edge server variability
    for attempt in range(3):
        for group in PQC_GROUPS:
            try:
                result = subprocess.run(
                    [OPENSSL_BIN, "s_client",
                     "-connect", f"{domain}:443",
                     "-servername", domain,
                     "-groups", group],
                    input=b"",
                    capture_output=True,
                    timeout=10
                )
                output = result.stdout.decode('utf-8', errors='replace') + result.stderr.decode('utf-8', errors='replace')

                if "passed invalid argument" in output or "cannot be set" in output:
                    continue

                for line in output.split('\n'):
                    if "Negotiated TLS1.3 group:" in line:
                        negotiated = line.split(":", 1)[-1].strip()
                        if negotiated and negotiated != "<NULL>" and negotiated != "":
                            if any(pqc in negotiated.upper() for pqc in ["KYBER", "MLKEM", "ML-KEM", "ML_KEM"]):
                                pqc_result["supported"] = True
                                pqc_result["group"] = negotiated
                                pqc_result["details"] = f"PQC hybrid negotiated: {negotiated}"
                                _scan_cache[domain] = pqc_result
                                return pqc_result

                for line in output.split('\n'):
                    if "Server Temp Key:" in line:
                        temp_key = line.split(":", 1)[-1].strip()
                        if any(pqc in temp_key.lower() for pqc in ["kyber", "mlkem", "ml-kem"]):
                            pqc_result["supported"] = True
                            pqc_result["group"] = group
                            pqc_result["details"] = f"PQC hybrid negotiated: {temp_key}"
                            _scan_cache[domain] = pqc_result
                            return pqc_result

            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue

    pqc_result["details"] = f"Tested PQC groups ({len(PQC_GROUPS)} groups x 3 attempts), none supported by server"
    _scan_cache[domain] = pqc_result
    return pqc_result


# --- Enhanced scanning with openssl subprocess ---
def get_cert_details(domain: str) -> dict:
    """Get detailed certificate info using openssl."""
    try:
        result = subprocess.run(
            [OPENSSL_BIN, "s_client", "-connect", f"{domain}:443", "-servername", domain],
            input=b"",
            capture_output=True,
            timeout=10
        )
        output = result.stdout.decode('utf-8', errors='replace') + result.stderr.decode('utf-8', errors='replace')

        details = {
            "sig_algorithm": "Unknown",
            "key_type": "Unknown",
            "key_size": 0,
            "protocol": "Unknown",
            "cipher": "Unknown",
            "cipher_bits": 0,
        }

        for line in output.split('\n'):
            line = line.strip()
            if 'Peer signature type:' in line:
                details["sig_type"] = line.split(':')[-1].strip()
            if 'Server Temp Key:' in line:
                details["temp_key"] = line.split(':',1)[-1].strip()
            if 'Protocol' in line and 'TLS' in line:
                details["protocol"] = line.split(':')[-1].strip()
            if 'Cipher' in line and 'is' in line:
                parts = line.split('is')
                if len(parts) > 1:
                    details["cipher"] = parts[-1].strip()

        # Get certificate text for signature algorithm
        cert_result = subprocess.run(
            [OPENSSL_BIN, "s_client", "-connect", f"{domain}:443", "-servername", domain],
            input=b"",
            capture_output=True,
            timeout=10
        )

        # Extract and decode certificate
        cert_pem = ""
        in_cert = False
        for line in cert_result.stdout.decode('utf-8', errors='replace').split('\n'):
            if '-----BEGIN CERTIFICATE-----' in line:
                in_cert = True
            if in_cert:
                cert_pem += line + '\n'
            if '-----END CERTIFICATE-----' in line:
                break

        if cert_pem:
            cert_text = subprocess.run(
                [OPENSSL_BIN, "x509", "-text", "-noout"],
                input=cert_pem.encode(),
                capture_output=True,
                timeout=5
            )
            cert_output = cert_text.stdout.decode('utf-8', errors='replace')
            for line in cert_output.split('\n'):
                line = line.strip()
                if 'Signature Algorithm:' in line:
                    details["sig_algorithm"] = line.split(':')[-1].strip()
                if 'Public Key Algorithm:' in line:
                    details["key_type"] = line.split(':')[-1].strip()
                if 'Public-Key:' in line or 'RSA Public-Key:' in line:
                    try:
                        size = ''.join(filter(str.isdigit, line.split('(')[-1]))
                        if size:
                            details["key_size"] = int(size)
                    except (ValueError, IndexError):
                        pass

        return details
    except Exception as e:
        return {"error": str(e)}


CDN_SIGNATURES = {
    "Cloudflare": {
        "issuers": ["Cloudflare", "CloudFlare"],
        "headers": ["cloudflare"],
        "note": "Cloudflare enables PQC hybrid by default on all zones since Oct 2024"
    },
    "Akamai": {
        "issuers": ["Akamai"],
        "headers": ["akamai", "akamaized"],
        "note": "Akamai CDN may provide PQC at the edge"
    },
    "AWS CloudFront": {
        "issuers": ["Amazon", "AWS"],
        "headers": ["cloudfront", "amz"],
        "note": "AWS CloudFront supports PQC via s2n-tls"
    },
    "Google Cloud": {
        "issuers": ["Google Trust Services", "GTS"],
        "headers": ["google", "gws"],
        "note": "Google infrastructure supports PQC hybrid natively"
    },
    "Fastly": {
        "issuers": ["Fastly", "GlobalSign"],
        "headers": ["fastly"],
        "note": "Fastly CDN"
    },
    "Azure CDN": {
        "issuers": ["Microsoft"],
        "headers": ["azure", "msedge"],
        "note": "Microsoft Azure CDN"
    },
}


def detect_cdn(domain: str, cert_issuer: str) -> dict:
    """Detect if a domain is behind a CDN based on cert issuer and HTTP headers."""
    cached = _cache_get(_cdn_cache, domain)
    if cached:
        return cached

    result = {"detected": False, "provider": None, "note": None}

    # Check cert issuer
    issuer_upper = (cert_issuer or "").upper()
    for cdn, sigs in CDN_SIGNATURES.items():
        for iss in sigs["issuers"]:
            if iss.upper() in issuer_upper:
                result["detected"] = True
                result["provider"] = cdn
                result["note"] = sigs["note"]
                _cdn_cache[domain] = result
                return result

    # Check HTTP headers
    try:
        import http.client
        conn = http.client.HTTPSConnection(domain, timeout=5, context=ssl.create_default_context())
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v.lower() for k, v in resp.getheaders()}
        server = headers.get("server", "")
        via = headers.get("via", "")
        cdn_header = headers.get("x-cdn", "")
        all_headers = f"{server} {via} {cdn_header}"

        for cdn, sigs in CDN_SIGNATURES.items():
            for h in sigs["headers"]:
                if h in all_headers:
                    result["detected"] = True
                    result["provider"] = cdn
                    result["note"] = sigs["note"]
                    _cache_set(_cdn_cache, domain, result)
                    return result
        conn.close()
    except (socket.error, ssl.SSLError, OSError):
        pass

    _cdn_cache[domain] = result
    return result


def scan_domain(domain: str) -> dict:
    """Comprehensive domain scan."""
    results = {
        "domain": domain,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "tls_version": None,
        "certificate": {},
        "cipher_suite": None,
        "cert_details": {},
        "all_ciphers_13": [],
        "all_ciphers_12": [],
        "error": None
    }

    try:
        # Standard Python SSL scan
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                results["tls_version"] = ssock.version()

                cipher = ssock.cipher()
                if cipher:
                    results["cipher_suite"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2]
                    }

                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    results["certificate"] = {
                        "subject": subject.get('commonName', 'N/A'),
                        "issuer": issuer.get('organizationName', 'N/A'),
                        "not_before": cert.get('notBefore', 'N/A'),
                        "not_after": cert.get('notAfter', 'N/A'),
                        "serial": cert.get('serialNumber', 'N/A'),
                    }

                try:
                    shared = ssock.shared_ciphers()
                    if shared:
                        results["all_ciphers_13"] = [c[0] for c in shared if 'TLS_' in c[0]]
                        results["all_ciphers_12"] = [c[0] for c in shared if 'TLS_' not in c[0]]
                except (socket.error, ssl.SSLError, OSError):
                    pass

        # Enhanced scan via openssl
        results["cert_details"] = get_cert_details(domain)

        # PQC probe (only if OpenSSL supports it)
        results["pqc_probe"] = probe_pqc_support(domain)

        # CDN detection
        cert_issuer = results["certificate"].get("issuer", "")
        results["cdn"] = detect_cdn(domain, cert_issuer)

    except ssl.SSLError as e:
        results["error"] = f"SSL Error: {str(e)}"
    except socket.timeout:
        results["error"] = "Connection timed out"
    except socket.gaierror:
        results["error"] = f"DNS resolution failed for {domain}"
    except ConnectionRefusedError:
        results["error"] = f"Connection refused by {domain}"
    except Exception as e:
        results["error"] = f"Error: {str(e)}"

    return results


def analyze_pqc_readiness(results: dict) -> dict:
    """Dual-score analysis: Classical Security + PQC Readiness."""
    analysis = {
        "classical_score": 0,    # 0-100: how good is current crypto
        "pqc_score": 0,          # 0-100: how ready for quantum
        "classical_grade": "F",
        "pqc_grade": "F",
        "findings": [],
        "critical_count": 0,
        "moderate_count": 0,
        "safe_count": 0
    }

    if results.get("error"):
        return analysis

    c_score = 0  # classical
    p_score = 0  # pqc readiness

    cipher_name = results.get("cipher_suite", {}).get("name", "")
    cipher_bits = results.get("cipher_suite", {}).get("bits", 0)
    tls = results.get("tls_version", "")
    cert_details = results.get("cert_details", {})
    sig_algo = cert_details.get("sig_algorithm", "Unknown")
    key_type = cert_details.get("key_type", "Unknown")
    key_size = cert_details.get("key_size", 0)
    temp_key = cert_details.get("temp_key", "")

    # ===== 1. TLS VERSION =====
    if tls == "TLSv1.3":
        c_score += 25
        p_score += 20  # TLS 1.3 required for PQC hybrid
        analysis["findings"].append({
            "component": "TLS Version",
            "value": tls,
            "classical": "EXCELLENT",
            "pqc": "READY",
            "detail": "TLS 1.3 is required for PQC hybrid key exchange. Best foundation for migration."
        })
        analysis["safe_count"] += 1
    elif tls == "TLSv1.2":
        c_score += 15
        p_score += 5
        analysis["findings"].append({
            "component": "TLS Version",
            "value": tls,
            "classical": "ACCEPTABLE",
            "pqc": "UPGRADE NEEDED",
            "detail": "TLS 1.2 cannot support PQC hybrid key exchange. Upgrade to TLS 1.3 before PQC migration."
        })
        analysis["moderate_count"] += 1
    else:
        c_score += 0
        p_score += 0
        analysis["findings"].append({
            "component": "TLS Version",
            "value": tls or "Unknown",
            "classical": "CRITICAL",
            "pqc": "BLOCKED",
            "detail": "Outdated TLS. Vulnerable to classical attacks today. PQC migration impossible without TLS upgrade."
        })
        analysis["critical_count"] += 1

    # ===== 2. KEY EXCHANGE =====
    if "ECDHE" in cipher_name.upper() or "X25519" in temp_key.upper() or "ECDH" in temp_key.upper():
        kex_info = temp_key if temp_key else "ECDHE"
        c_score += 25  # Forward secrecy, best classical
        p_score += 10  # Good baseline but quantum-vulnerable
        analysis["findings"].append({
            "component": "Key Exchange",
            "value": kex_info,
            "classical": "EXCELLENT",
            "pqc": "QUANTUM-VULNERABLE",
            "detail": f"Forward secrecy via {kex_info}. Best classical practice but Shor's algorithm breaks this. Migrate to ML-KEM hybrid (X25519+ML-KEM-768).",
            "migration": "X25519+ML-KEM-768 (NIST FIPS 203) hybrid key exchange",
            "timeline": "Deploy by 2028"
        })
        analysis["moderate_count"] += 1
    elif "DHE" in cipher_name.upper():
        c_score += 10
        p_score += 5
        analysis["findings"].append({
            "component": "Key Exchange",
            "value": "DHE",
            "classical": "WEAK",
            "pqc": "QUANTUM-VULNERABLE",
            "detail": "DHE provides forward secrecy but is slower and less secure than ECDHE. Quantum-vulnerable.",
            "migration": "Step 1: ECDHE. Step 2: ML-KEM (FIPS 203)",
            "timeline": "Upgrade to ECDHE now"
        })
        analysis["critical_count"] += 1
    elif "RSA" in cipher_name.upper():
        c_score += 0
        p_score += 0
        analysis["findings"].append({
            "component": "Key Exchange",
            "value": "RSA (static)",
            "classical": "CRITICAL",
            "pqc": "QUANTUM-VULNERABLE",
            "detail": "No forward secrecy. Past traffic can be decrypted if key is compromised. Highest quantum risk.",
            "migration": "Step 1: ECDHE. Step 2: ML-KEM (FIPS 203)",
            "timeline": "Upgrade immediately"
        })
        analysis["critical_count"] += 1

    # ===== 3. SYMMETRIC CIPHER =====
    if "AES_256" in cipher_name.upper() or "AES256" in cipher_name.upper():
        c_score += 20
        p_score += 20  # AES-256 is quantum-safe
        analysis["findings"].append({
            "component": "Symmetric Encryption",
            "value": "AES-256",
            "classical": "EXCELLENT",
            "pqc": "QUANTUM-SAFE",
            "detail": "AES-256 provides 128-bit security against Grover's algorithm. No migration needed."
        })
        analysis["safe_count"] += 1
    elif "CHACHA20" in cipher_name.upper():
        c_score += 20
        p_score += 20
        analysis["findings"].append({
            "component": "Symmetric Encryption",
            "value": "ChaCha20-Poly1305",
            "classical": "EXCELLENT",
            "pqc": "QUANTUM-SAFE",
            "detail": "256-bit symmetric key. Quantum-safe. No migration needed."
        })
        analysis["safe_count"] += 1
    elif "AES_128" in cipher_name.upper() or "AES128" in cipher_name.upper():
        c_score += 15
        p_score += 10
        analysis["findings"].append({
            "component": "Symmetric Encryption",
            "value": "AES-128",
            "classical": "GOOD",
            "pqc": "UPGRADE RECOMMENDED",
            "detail": "AES-128 reduced to 64-bit effective security by Grover's algorithm. Upgrade to AES-256.",
            "migration": "AES-256-GCM",
            "timeline": "Upgrade when convenient"
        })
        analysis["moderate_count"] += 1

    # ===== 4. CERTIFICATE SIGNATURE =====
    is_ecdsa = "ecdsa" in sig_algo.lower() or "ec" in key_type.lower()
    is_rsa = "rsa" in sig_algo.lower() or "rsa" in key_type.lower()

    if is_ecdsa:
        c_score += 20
        p_score += 5  # Better than RSA but still quantum-vulnerable
        analysis["findings"].append({
            "component": "Certificate Signature",
            "value": f"{sig_algo} ({key_type}, {key_size}-bit)" if key_size else sig_algo,
            "classical": "EXCELLENT",
            "pqc": "QUANTUM-VULNERABLE",
            "detail": "ECDSA is best classical practice for signatures. Smaller, faster than RSA. But broken by Shor's algorithm.",
            "migration": "ML-DSA / CRYSTALS-Dilithium (NIST FIPS 204)",
            "timeline": "Plan migration by 2028"
        })
        analysis["moderate_count"] += 1
    elif is_rsa:
        size_note = f" ({key_size}-bit)" if key_size else ""
        if key_size >= 4096:
            c_score += 18
        elif key_size >= 2048:
            c_score += 15
        else:
            c_score += 8
        p_score += 3
        analysis["findings"].append({
            "component": "Certificate Signature",
            "value": f"{sig_algo}{size_note}",
            "classical": "GOOD" if key_size >= 2048 else "WEAK",
            "pqc": "QUANTUM-VULNERABLE",
            "detail": f"RSA{size_note} signatures. Quantum-vulnerable via Shor's algorithm. Larger key does not help against quantum.",
            "migration": "ML-DSA / CRYSTALS-Dilithium (NIST FIPS 204)",
            "timeline": "Plan migration by 2028"
        })
        analysis["moderate_count"] += 1
    else:
        c_score += 10
        p_score += 3
        analysis["findings"].append({
            "component": "Certificate Signature",
            "value": sig_algo or "Could not determine",
            "classical": "UNKNOWN",
            "pqc": "LIKELY VULNERABLE",
            "detail": "Could not determine exact signature algorithm. Most PKI certificates use RSA or ECDSA, both quantum-vulnerable.",
            "migration": "ML-DSA / CRYSTALS-Dilithium (NIST FIPS 204)",
            "timeline": "Investigate and plan migration"
        })
        analysis["moderate_count"] += 1

    # ===== 5. PQC HYBRID DETECTION =====
    pqc_detected = False
    pqc_algo = ""

    # Method 1: Check PQC probe results (most reliable if OpenSSL 3.5+)
    pqc_probe = results.get("pqc_probe", {})
    if pqc_probe.get("supported"):
        pqc_detected = True
        pqc_algo = pqc_probe.get("group", "ML-KEM hybrid")

    # Method 2: Check temp key from standard openssl scan
    if not pqc_detected and temp_key:
        for pqc_name in ["Kyber", "ML-KEM", "MLKEM", "kyber", "mlkem"]:
            if pqc_name.lower() in temp_key.lower():
                pqc_detected = True
                pqc_algo = temp_key
                break

    # Method 3: Check cipher names
    if not pqc_detected:
        all_ciphers = results.get("all_ciphers_13", []) + results.get("all_ciphers_12", [])
        for c in all_ciphers:
            for pqc_name in ["KYBER", "MLKEM", "ML_KEM", "DILITHIUM", "ML_DSA"]:
                if pqc_name in c.upper():
                    pqc_detected = True
                    pqc_algo = c
                    break

    # Check CDN for PQC context
    cdn_info = results.get("cdn", {})
    cdn_detected = cdn_info.get("detected", False)
    cdn_provider = cdn_info.get("provider", "")

    if pqc_detected:
        p_score += 40
        detail_text = pqc_probe.get("details", "Post-quantum hybrid key exchange detected.")
        if cdn_detected:
            cdn_note = f" **Note:** This domain is behind {cdn_provider}. The PQC support likely comes from the CDN infrastructure, not the organization's own servers. Results may vary between scans due to CDN edge server rotation."
            pqc_label = "PQC-READY (via CDN)"
        else:
            cdn_note = ""
            pqc_label = "PQC-READY"
        analysis["findings"].append({
            "component": "PQC Hybrid Key Exchange",
            "value": f"DETECTED: {pqc_algo}",
            "classical": "N/A",
            "pqc": pqc_label,
            "detail": f"{detail_text} This server is among the <5% globally that have deployed PQC.{cdn_note}"
        })
        analysis["safe_count"] += 1
    else:
        p_score += 0
        if pqc_probe.get("openssl_pqc_capable"):
            detail_text = f"Tested {len(PQC_GROUPS)} PQC key exchange groups (3 attempts each). None accepted by server."
            if cdn_detected:
                detail_text += f" Note: this domain is behind {cdn_provider}. Some CDN edge servers may support PQC while others don't -- results can vary between scans."
        else:
            detail_text = f"Detection limited by OpenSSL version ({pqc_probe.get('openssl_version', 'unknown')}). The server may support PQC via newer clients (Chrome 124+)."

        analysis["findings"].append({
            "component": "PQC Hybrid Key Exchange",
            "value": "NOT DETECTED",
            "classical": "N/A",
            "pqc": "NOT DEPLOYED",
            "detail": detail_text,
            "migration": "Deploy X25519+ML-KEM-768 hybrid via TLS 1.3",
            "timeline": "Target 2027-2028"
        })
        analysis["moderate_count"] += 1

    # ===== 6. HASH ALGORITHM =====
    if "SHA384" in cipher_name.upper() or "SHA-384" in cipher_name.upper():
        c_score += 10
        p_score += 5
        analysis["findings"].append({
            "component": "Hash Algorithm",
            "value": "SHA-384",
            "classical": "EXCELLENT",
            "pqc": "QUANTUM-SAFE",
            "detail": "SHA-384 provides adequate collision resistance post-quantum."
        })
        analysis["safe_count"] += 1
    elif "SHA256" in cipher_name.upper() or "SHA-256" in cipher_name.upper():
        c_score += 10
        p_score += 5
        analysis["findings"].append({
            "component": "Hash Algorithm",
            "value": "SHA-256",
            "classical": "EXCELLENT",
            "pqc": "QUANTUM-SAFE",
            "detail": "SHA-256 provides adequate collision resistance post-quantum."
        })
        analysis["safe_count"] += 1

    # ===== CALCULATE GRADES =====
    analysis["classical_score"] = min(100, c_score)
    analysis["pqc_score"] = min(100, p_score)

    def score_to_grade(score):
        if score >= 90: return "A+"
        if score >= 80: return "A"
        if score >= 70: return "B"
        if score >= 60: return "C"
        if score >= 45: return "D"
        if score >= 30: return "E"
        return "F"

    analysis["classical_grade"] = score_to_grade(analysis["classical_score"])
    analysis["pqc_grade"] = score_to_grade(analysis["pqc_score"])

    # Recommendations
    analysis["recommendations"] = generate_recommendations(analysis)

    return analysis


def generate_recommendations(analysis: dict) -> list:
    recs = []

    if analysis["pqc_score"] < 30:
        recs.append({
            "priority": "IMMEDIATE",
            "action": "Conduct a cryptographic inventory",
            "detail": "Map all cryptographic algorithms across your infrastructure. Identify systems handling data with >5-year confidentiality requirements."
        })

    if analysis["classical_score"] < 60:
        recs.append({
            "priority": "IMMEDIATE",
            "action": "Upgrade classical cryptography first",
            "detail": "Your current cryptographic configuration has classical weaknesses. Fix these before attempting PQC migration: upgrade to TLS 1.3, ECDHE key exchange, AES-256."
        })

    recs.append({
        "priority": "HIGH",
        "action": "Develop a PQC migration roadmap",
        "detail": "Create a phased plan: (1) TLS 1.3 everywhere, (2) AES-256 for symmetric, (3) hybrid key exchange X25519+ML-KEM-768, (4) PQC certificates when CAs support them."
    })

    recs.append({
        "priority": "HIGH",
        "action": "Assess 'Harvest Now, Decrypt Later' exposure",
        "detail": "Data encrypted today with RSA/ECDHE can be recorded and decrypted when quantum computers arrive. Prioritize PQC for data requiring >5 years of confidentiality."
    })

    if analysis["pqc_score"] >= 30:
        recs.append({
            "priority": "MEDIUM",
            "action": "Test PQC hybrid key exchange",
            "detail": "Enable X25519+ML-KEM-768 hybrid in a staging environment. Chrome 124+, Firefox 128+, and Cloudflare already support this. Test for performance and compatibility."
        })

    recs.append({
        "priority": "MEDIUM",
        "action": "Monitor NIST and ANSSI PQC guidance",
        "detail": "NIST FIPS 203/204/205 are finalized. ANSSI has published specific migration recommendations for French organizations. Align your roadmap with these standards."
    })

    return recs


def generate_share_card(domain: str, classical_grade: str, pqc_grade: str, classical_score: int, pqc_score: int) -> str:
    """Generate an HTML share card."""
    c_color = "#10b981" if classical_score >= 70 else "#f59e0b" if classical_score >= 45 else "#dc2626"
    p_color = "#10b981" if pqc_score >= 70 else "#f59e0b" if pqc_score >= 45 else "#dc2626"

    card_html = f"""
    <div style="background: linear-gradient(135deg, #0f172a, #1e293b); border-radius: 16px; padding: 32px; color: white; max-width: 600px; margin: 20px auto; font-family: -apple-system, sans-serif;">
        <div style="text-align: center; margin-bottom: 20px;">
            <span style="font-size: 0.85rem; text-transform: uppercase; letter-spacing: 2px; color: #94a3b8;">PQC Readiness Report</span>
        </div>
        <div style="text-align: center; margin-bottom: 24px;">
            <span style="font-size: 1.8rem; font-weight: 700;">{domain}</span>
        </div>
        <div style="display: flex; justify-content: center; gap: 40px; margin-bottom: 24px;">
            <div style="text-align: center;">
                <div style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin-bottom: 8px;">Classical Security</div>
                <div style="font-size: 3.5rem; font-weight: 800; color: {c_color};">{classical_grade}</div>
                <div style="font-size: 0.9rem; color: #94a3b8;">{classical_score}/100</div>
            </div>
            <div style="width: 1px; background: #334155;"></div>
            <div style="text-align: center;">
                <div style="font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; margin-bottom: 8px;">PQC Readiness</div>
                <div style="font-size: 3.5rem; font-weight: 800; color: {p_color};">{pqc_grade}</div>
                <div style="font-size: 0.9rem; color: #94a3b8;">{pqc_score}/100</div>
            </div>
        </div>
        <div style="text-align: center; border-top: 1px solid #334155; padding-top: 16px;">
            <span style="font-size: 0.75rem; color: #64748b;">Scanned {datetime.now().strftime('%B %d, %Y')} | pqc-scanner.streamlit.app | Built by Amin Hasbini</span>
        </div>
    </div>
    """
    return card_html


def generate_share_card_png(domain: str, classical_grade: str, pqc_grade: str,
                             classical_score: int, pqc_score: int) -> bytes:
    """Generate a 1200x627 PNG share card (LinkedIn optimal size) using Pillow."""
    width, height = 1200, 627

    img = Image.new('RGB', (width, height), color=(15, 23, 42))
    draw = ImageDraw.Draw(img)

    # Gradient background: blend from #0f172a to #1e293b top to bottom
    for y in range(height):
        ratio = y / height
        r = int(15 + (30 - 15) * ratio)
        g = int(23 + (41 - 23) * ratio)
        b = int(42 + (59 - 42) * ratio)
        draw.line([(0, y), (width, y)], fill=(r, g, b))

    # Load fonts (use default if custom not available)
    try:
        font_large = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 64)
        font_medium = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 40)
        font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 22)
        font_header = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 18)
        font_grade = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 96)
    except (OSError, IOError):
        try:
            font_large = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 64)
            font_medium = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 40)
            font_small = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 22)
            font_header = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 18)
            font_grade = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 96)
        except (OSError, IOError):
            font_large = ImageFont.load_default()
            font_medium = ImageFont.load_default()
            font_small = ImageFont.load_default()
            font_header = ImageFont.load_default()
            font_grade = ImageFont.load_default()

    # Grade color helper
    def grade_color(score):
        if score >= 70:
            return (16, 185, 129)  # green
        elif score >= 45:
            return (245, 158, 11)  # amber
        else:
            return (220, 38, 38)   # red

    # Header: "PQC READINESS REPORT"
    header_text = "PQC READINESS REPORT"
    bbox = draw.textbbox((0, 0), header_text, font=font_header)
    tw = bbox[2] - bbox[0]
    draw.text(((width - tw) / 2, 40), header_text, fill=(148, 163, 184), font=font_header)

    # Domain name large and centered
    bbox = draw.textbbox((0, 0), domain, font=font_large)
    tw = bbox[2] - bbox[0]
    draw.text(((width - tw) / 2, 80), domain, fill=(255, 255, 255), font=font_large)

    # Divider line
    draw.line([(200, 170), (width - 200, 170)], fill=(51, 65, 85), width=2)

    # Grade boxes side by side
    c_color = grade_color(classical_score)
    p_color = grade_color(pqc_score)

    # Left box: Classical Security
    box_y = 200
    box_w = 360
    box_h = 280
    left_x = width // 2 - box_w - 40
    right_x = width // 2 + 40

    # Classical box background
    draw.rounded_rectangle([left_x, box_y, left_x + box_w, box_y + box_h],
                           radius=16, fill=(30, 41, 59), outline=c_color, width=2)
    # Classical label
    cls_label = "Classical Security"
    bbox = draw.textbbox((0, 0), cls_label, font=font_header)
    tw = bbox[2] - bbox[0]
    draw.text((left_x + (box_w - tw) / 2, box_y + 20), cls_label, fill=(148, 163, 184), font=font_header)
    # Classical grade
    bbox = draw.textbbox((0, 0), classical_grade, font=font_grade)
    tw = bbox[2] - bbox[0]
    draw.text((left_x + (box_w - tw) / 2, box_y + 60), classical_grade, fill=c_color, font=font_grade)
    # Classical score
    score_text = f"{classical_score}/100"
    bbox = draw.textbbox((0, 0), score_text, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((left_x + (box_w - tw) / 2, box_y + 200), score_text, fill=(148, 163, 184), font=font_small)

    # PQC box background
    draw.rounded_rectangle([right_x, box_y, right_x + box_w, box_y + box_h],
                           radius=16, fill=(30, 41, 59), outline=p_color, width=2)
    # PQC label
    pqc_label = "PQC Readiness"
    bbox = draw.textbbox((0, 0), pqc_label, font=font_header)
    tw = bbox[2] - bbox[0]
    draw.text((right_x + (box_w - tw) / 2, box_y + 20), pqc_label, fill=(148, 163, 184), font=font_header)
    # PQC grade
    bbox = draw.textbbox((0, 0), pqc_grade, font=font_grade)
    tw = bbox[2] - bbox[0]
    draw.text((right_x + (box_w - tw) / 2, box_y + 60), pqc_grade, fill=p_color, font=font_grade)
    # PQC score
    score_text = f"{pqc_score}/100"
    bbox = draw.textbbox((0, 0), score_text, font=font_small)
    tw = bbox[2] - bbox[0]
    draw.text((right_x + (box_w - tw) / 2, box_y + 200), score_text, fill=(148, 163, 184), font=font_small)

    # Footer
    footer_text = f"Scanned {datetime.now().strftime('%B %d, %Y')} | pqc-scanner.streamlit.app | Built by Amin Hasbini"
    bbox = draw.textbbox((0, 0), footer_text, font=font_header)
    tw = bbox[2] - bbox[0]
    draw.line([(200, height - 60), (width - 200, height - 60)], fill=(51, 65, 85), width=1)
    draw.text(((width - tw) / 2, height - 45), footer_text, fill=(100, 116, 139), font=font_header)

    buf = BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def generate_verdict(classical_score: int, pqc_score: int, classical_grade: str, pqc_grade: str, lang_code: str = "en") -> dict:
    """Generate a plain-language verdict based on the dual scores."""
    # Determine classical level
    if classical_score >= 70:
        c_level = "strong"
    elif classical_score >= 45:
        c_level = "moderate"
    else:
        c_level = "weak"

    # Determine PQC level
    if pqc_score >= 70:
        p_level = "strong"
    elif pqc_score >= 45:
        p_level = "moderate"
    else:
        p_level = "weak"

    verdicts = {
        ("strong", "strong"): {
            "color": "#10b981",
            "icon": "shield",
            "en": "Excellent. Your site uses modern cryptography with post-quantum hybrid key exchange deployed. You are among the top 5% of websites globally for quantum readiness.",
            "fr": "Excellent. Votre site utilise une cryptographie moderne avec un echange de cles hybride post-quantique deploye. Vous faites partie des 5% de sites les mieux prepares au monde."
        },
        ("strong", "moderate"): {
            "color": "#f59e0b",
            "icon": "warning",
            "en": "Your classical security is solid, and you have a good foundation for PQC migration. Continue deploying hybrid key exchange (X25519+ML-KEM-768) across all services to complete your quantum readiness.",
            "fr": "Votre securite classique est solide et vous avez une bonne base pour la migration PQC. Continuez a deployer l'echange de cles hybride (X25519+ML-KEM-768) sur tous vos services."
        },
        ("strong", "weak"): {
            "color": "#dc2626",
            "icon": "alert",
            "en": "Your classical security is strong, but your data is currently vulnerable to 'Harvest Now, Decrypt Later' attacks. Adversaries recording your traffic today will be able to decrypt it when quantum computers arrive. Prioritize PQC hybrid key exchange deployment.",
            "fr": "Votre securite classique est forte, mais vos donnees sont actuellement vulnerables aux attaques 'Recolter Maintenant, Dechiffrer Plus Tard'. Les adversaires enregistrant votre trafic aujourd'hui pourront le dechiffrer a l'arrivee des ordinateurs quantiques. Priorisez le deploiement de l'echange de cles hybride PQC."
        },
        ("moderate", "moderate"): {
            "color": "#f59e0b",
            "icon": "warning",
            "en": "Your cryptographic configuration is functional but needs modernization. Upgrade to TLS 1.3 and AES-256 while planning PQC migration in parallel.",
            "fr": "Votre configuration cryptographique est fonctionnelle mais necessite une modernisation. Passez a TLS 1.3 et AES-256 tout en planifiant la migration PQC en parallele."
        },
        ("moderate", "weak"): {
            "color": "#dc2626",
            "icon": "alert",
            "en": "Your cryptographic configuration needs modernization. Upgrade to TLS 1.3 and AES-256 first, then plan PQC migration. Your data is exposed to both current and future quantum threats.",
            "fr": "Votre configuration cryptographique necessite une modernisation. Passez d'abord a TLS 1.3 et AES-256, puis planifiez la migration PQC. Vos donnees sont exposees aux menaces actuelles et futures quantiques."
        },
        ("weak", "weak"): {
            "color": "#dc2626",
            "icon": "alert",
            "en": "Critical: Your cryptographic configuration has significant weaknesses against both today's threats and future quantum attacks. Immediate action required: upgrade TLS, deploy modern ciphers, and begin cryptographic inventory for PQC migration.",
            "fr": "Critique : Votre configuration cryptographique presente des faiblesses significatives contre les menaces actuelles et futures quantiques. Action immediate requise : mettez a jour TLS, deployez des chiffrements modernes, et commencez l'inventaire cryptographique pour la migration PQC."
        },
        ("weak", "moderate"): {
            "color": "#dc2626",
            "icon": "alert",
            "en": "Your classical security needs urgent attention. While some PQC elements are present, fix the classical vulnerabilities first: upgrade to TLS 1.3, ECDHE, and AES-256.",
            "fr": "Votre securite classique necessite une attention urgente. Bien que certains elements PQC soient presents, corrigez d'abord les vulnerabilites classiques : passez a TLS 1.3, ECDHE et AES-256."
        },
        ("weak", "strong"): {
            "color": "#f59e0b",
            "icon": "warning",
            "en": "Unusual configuration: PQC hybrid is deployed but classical security has gaps. Ensure TLS 1.3, AES-256, and ECDHE are consistently configured across all endpoints.",
            "fr": "Configuration inhabituelle : le PQC hybride est deploye mais la securite classique presente des lacunes. Assurez-vous que TLS 1.3, AES-256 et ECDHE sont configures de maniere coherente sur tous les points d'acces."
        },
        ("moderate", "strong"): {
            "color": "#10b981",
            "icon": "shield",
            "en": "Good PQC readiness with room to improve classical security. Upgrade to AES-256 and ensure ECDHE is used everywhere for the strongest overall posture.",
            "fr": "Bonne maturite PQC avec une marge d'amelioration en securite classique. Passez a AES-256 et assurez-vous qu'ECDHE est utilise partout pour la meilleure posture globale."
        },
    }

    key = (c_level, p_level)
    verdict = verdicts.get(key, verdicts[("moderate", "weak")])
    text = verdict["fr"] if lang_code == "fr" else verdict["en"]

    return {"text": text, "color": verdict["color"], "icon": verdict["icon"]}


def generate_executive_summary_txt(domain: str, results: dict, analysis: dict) -> str:
    """Generate a plain-text executive summary report."""
    scan_date = datetime.now().strftime("%Y-%m-%d")

    lines = []
    lines.append("=" * 60)
    lines.append("PQC READINESS REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Domain:              {domain}")
    lines.append(f"Scan Date:           {scan_date}")
    lines.append(f"Classical Security:  {analysis['classical_grade']} ({analysis['classical_score']}/100)")
    lines.append(f"PQC Readiness:       {analysis['pqc_grade']} ({analysis['pqc_score']}/100)")
    lines.append("")

    # TLS info
    lines.append("-" * 60)
    lines.append("CONNECTION DETAILS")
    lines.append("-" * 60)
    lines.append(f"TLS Version:         {results.get('tls_version', 'N/A')}")
    cipher_suite = results.get('cipher_suite', {})
    lines.append(f"Cipher Suite:        {cipher_suite.get('name', 'N/A')}")
    lines.append(f"Key Bits:            {cipher_suite.get('bits', 'N/A')}")
    cert_details = results.get('cert_details', {})
    lines.append(f"Cert Signature:      {cert_details.get('sig_algorithm', 'N/A')}")
    cert = results.get('certificate', {})
    lines.append(f"Cert Issuer:         {cert.get('issuer', 'N/A')}")
    lines.append(f"Valid Until:         {cert.get('not_after', 'N/A')}")
    cdn_info = results.get('cdn', {})
    if cdn_info.get('detected'):
        lines.append(f"CDN:                 {cdn_info.get('provider', 'Unknown')}")
    lines.append("")

    # Findings
    lines.append("-" * 60)
    lines.append("FINDINGS")
    lines.append("-" * 60)
    for f in analysis.get("findings", []):
        component = f.get("component", "")
        value = f.get("value", "")
        classical = f.get("classical", "")
        pqc = f.get("pqc", "")
        lines.append(f"  [{component}]")
        lines.append(f"    Value:     {value}")
        lines.append(f"    Classical: {classical}")
        lines.append(f"    PQC:       {pqc}")
        if f.get("migration"):
            lines.append(f"    Migration: {f['migration']}")
        if f.get("timeline"):
            lines.append(f"    Timeline:  {f['timeline']}")
        lines.append("")

    # Recommendations
    lines.append("-" * 60)
    lines.append("RECOMMENDATIONS")
    lines.append("-" * 60)
    for i, rec in enumerate(analysis.get("recommendations", []), 1):
        lines.append(f"  {i}. [{rec['priority']}] {rec['action']}")
        lines.append(f"     {rec['detail']}")
        lines.append("")

    # Footer
    lines.append("=" * 60)
    lines.append("Built by Amin Hasbini | pqc-scanner.streamlit.app")
    lines.append("AI & Cybersecurity Strategy Executive")
    lines.append("=" * 60)

    return "\n".join(lines)


# --- HARVEST NOW DECRYPT LATER DATA ---
HARVEST_NOW_SECTORS = {
    "Banking & Finance": {"risk": "VERY HIGH", "data_lifetime": "7-30 years", "note": "Transaction records, customer data, regulatory archives"},
    "Healthcare": {"risk": "VERY HIGH", "data_lifetime": "Lifetime+", "note": "Patient records, genomic data, research IP"},
    "Government & Defense": {"risk": "VERY HIGH", "data_lifetime": "25-75 years", "note": "Classified communications, intelligence, diplomatic cables"},
    "Energy & Critical Infrastructure": {"risk": "HIGH", "data_lifetime": "10-30 years", "note": "SCADA protocols, grid configurations, operational data"},
    "Telecommunications": {"risk": "HIGH", "data_lifetime": "5-15 years", "note": "Metadata, routing tables, subscriber data"},
    "Legal & IP": {"risk": "HIGH", "data_lifetime": "20+ years", "note": "Patents, M&A data, privileged communications"},
    "Technology": {"risk": "MODERATE", "data_lifetime": "3-10 years", "note": "Source code, architecture docs, API keys"},
    "Retail & Consumer": {"risk": "MODERATE", "data_lifetime": "2-7 years", "note": "Payment data, customer profiles"},
}


# ============================================================
# STREAMLIT UI
# ============================================================

st.markdown("""
<style>
    /* Hide GitHub fork/star buttons and Streamlit toolbar */
    .stAppToolbar, [data-testid="stToolbar"],
    .styles_viewerBadge__CvC9N, ._profileContainer_gzau3_53,
    [data-testid="stDecoration"], #MainMenu,
    header[data-testid="stHeader"] .stAppToolbar,
    div[class*="stToolbar"] { display: none !important; }
    .main-header { font-size: 2.2rem; font-weight: 700; color: #1a1a2e; margin-bottom: 0; }
    .sub-header { font-size: 1.1rem; color: #555; margin-top: 0; margin-bottom: 2rem; }
    .finding-critical { background-color: #fee2e2; border-left: 4px solid #dc2626; padding: 12px 16px; border-radius: 4px; margin: 8px 0; }
    .finding-warning { background-color: #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 4px; margin: 8px 0; }
    .finding-safe { background-color: #d1fae5; border-left: 4px solid #10b981; padding: 12px 16px; border-radius: 4px; margin: 8px 0; }
    .finding-info { background-color: #dbeafe; border-left: 4px solid #3b82f6; padding: 12px 16px; border-radius: 4px; margin: 8px 0; }
    .grade-box { text-align: center; padding: 20px; border-radius: 12px; }
    .metric-box { text-align: center; padding: 15px; border-radius: 8px; background: #f8fafc; border: 1px solid #e2e8f0; }
    .footer { text-align: center; color: #888; font-size: 0.85rem; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #e2e8f0; }
</style>
""", unsafe_allow_html=True)

# Sidebar (language selector at top)
with st.sidebar:
    try:
        lang = st.segmented_control("🌐", ["English", "Français"], default="English", label_visibility="collapsed")
    except AttributeError:
        lang = st.radio("🌐", ["English", "Français"], index=0, horizontal=True, label_visibility="collapsed")
    lang_code = "fr" if lang == "Français" else "en"
    t = TEXTS[lang_code]

# Header
st.markdown(f'<p class="main-header">{t["title"]}</p>', unsafe_allow_html=True)
st.markdown(f'<p class="sub-header">{t["subtitle"]}</p>', unsafe_allow_html=True)

# Sidebar content
with st.sidebar:
    st.markdown(f"### {t['about']}")
    st.markdown(t["about_text"])

    st.markdown("---")
    st.markdown("### NIST PQC Standards (2024)")
    st.markdown("""
    - **FIPS 203**: ML-KEM (Kyber) -- Key Exchange
    - **FIPS 204**: ML-DSA (Dilithium) -- Signatures
    - **FIPS 205**: SLH-DSA (SPHINCS+) -- Signatures
    """)

    st.markdown("---")
    st.markdown(f"""
    **{t['built_by']} [Amin Hasbini](https://www.linkedin.com/in/amin-hasbini-cybersecurity/)**

    AI & Cybersecurity Strategy Executive | Ex-Kaspersky GReAT Director | OPECST Contributor
    """)

    current_history = load_scan_history()
    if current_history:
        st.markdown("---")
        st.markdown(f"**{len(current_history)}** {t['domains_scanned']}")

    # Runtime info
    st.markdown("---")
    st.caption(f"Python SSL: {ssl.OPENSSL_VERSION}")
    st.caption(f"Scanner binary: {OPENSSL_BIN}")
    st.caption(f"Scanner version: {OPENSSL_INFO['version']}")
    st.caption(f"PQC capable: {'Yes' if OPENSSL_INFO['pqc_capable'] else 'No'}")
    st.caption(f"PQC verified: {'Yes' if OPENSSL_INFO.get('pqc_verified') else 'No'}")


# --- CAC40 pre-scan data ---
CAC40_DATA_FILE = Path(__file__).parent / "cac40_results.json"
def load_cac40_data():
    if CAC40_DATA_FILE.exists():
        with open(CAC40_DATA_FILE, "r") as f:
            return json.load(f)
    return []

tab_cac40_label = "🏢 CAC40" if lang_code == "en" else "🏢 CAC 40"

# ===== DASHBOARD HERO SECTION =====
_dash_history = load_scan_history()
_dash_cac40 = load_cac40_data()
_dash_cac40_success = [r for r in _dash_cac40 if not r.get("error")]
_dash_cac40_pqc = sum(1 for r in _dash_cac40_success if r.get("pqc_hybrid"))

hero_col1, hero_col2, hero_col3 = st.columns(3)
with hero_col1:
    st.metric(
        label="Domaines scannés" if lang_code == "fr" else "Domains Scanned",
        value=str(len(_dash_history)),
    )
with hero_col2:
    if _dash_cac40_success:
        st.metric(
            label="CAC40 PQC Hybrid" if lang_code == "en" else "CAC 40 PQC Hybride",
            value=f"{_dash_cac40_pqc}/40",
            help="PQC via CDN ≠ organizational PQC readiness" if lang_code == "en" else "PQC via CDN ≠ maturite PQC organisationnelle",
        )
    else:
        st.metric(
            label="CAC40 PQC Hybrid" if lang_code == "en" else "CAC 40 PQC Hybride",
            value="--",
            help="Run a CAC40 scan first" if lang_code == "en" else "Lancez d'abord un scan CAC 40",
        )
with hero_col3:
    if lang_code == "fr":
        st.markdown("""
        <div style="background: linear-gradient(135deg, #3b82f622, #6366f122); border-radius: 12px; padding: 16px; text-align: center; border: 1px solid #3b82f644;">
            <div style="font-size: 1.1rem; font-weight: 600; color: #3b82f6;">Scannez votre domaine</div>
            <div style="font-size: 0.85rem; color: #666; margin-top: 4px;">Onglet Scanner ci-dessous</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background: linear-gradient(135deg, #3b82f622, #6366f122); border-radius: 12px; padding: 16px; text-align: center; border: 1px solid #3b82f644;">
            <div style="font-size: 1.1rem; font-weight: 600; color: #3b82f6;">Scan Your Domain</div>
            <div style="font-size: 0.85rem; color: #666; margin-top: 4px;">Use the Scanner tab below</div>
        </div>
        """, unsafe_allow_html=True)

st.markdown("")

# Main tabs
tab1, tab2, tab_cac, tab3, tab5, tab6 = st.tabs([
    t["tab_scanner"],
    t["tab_hndl"],
    tab_cac40_label,
    t["tab_cloud"],
    t["tab_ref"],
    t["tab_faq"],
])

# ===== TAB 1: SCANNER =====
with tab1:
    with st.form("scan_form"):
        col1, col2 = st.columns([3, 1])
        with col1:
            domain = st.text_input(t["enter_domain"], placeholder="example.com")
        with col2:
            st.markdown("<br>", unsafe_allow_html=True)
            scan_button = st.form_submit_button(t["scan_btn"], type="primary", use_container_width=True)

    # Recent scans
    recent = load_scan_history()
    if recent:
        st.markdown(f"**{t['recently_scanned']}**")
        display = recent[-8:]
        cols = st.columns(min(len(display), 8))
        for idx, scan in enumerate(reversed(display)):
            with cols[idx]:
                c_grade = scan.get("classical_grade", "?")
                p_grade = scan.get("pqc_grade", "?")
                c_color = "#10b981" if c_grade in ("A+","A","B") else "#f59e0b" if c_grade in ("C","D") else "#dc2626"
                p_color = "#10b981" if p_grade in ("A+","A","B") else "#f59e0b" if p_grade in ("C","D") else "#dc2626"
                cls_label = "Classique" if lang_code == "fr" else "Classical"
                pqc_label = "PQC"
                st.markdown(f"""<div style='font-size:0.85rem;line-height:1.6;'>
                    <strong>{scan['domain']}</strong><br>
                    {cls_label}: <span style='color:{c_color};font-weight:700;font-size:1.1rem;'>{c_grade}</span><br>
                    {pqc_label}: <span style='color:{p_color};font-weight:700;font-size:1.1rem;'>{p_grade}</span>
                </div>""", unsafe_allow_html=True)

    if scan_button and domain:
        domain = domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]

        with st.spinner(f"{t['scanning']} {domain}..."):
            results = scan_domain(domain)

            if results["error"]:
                st.error(f"{t['scan_failed']}: {results['error']}")
            else:
                analysis = analyze_pqc_readiness(results)

                # Save to history
                history = load_scan_history()
                history = [s for s in history if s["domain"] != domain]
                history.append({
                    "domain": domain,
                    "score": analysis["classical_score"],
                    "classical_grade": analysis["classical_grade"],
                    "pqc_grade": analysis["pqc_grade"],
                    "classical_score": analysis["classical_score"],
                    "pqc_score": analysis["pqc_score"],
                    "time": datetime.now(timezone.utc).isoformat()
                })
                save_scan_history(history)

                # ===== DUAL SCORE DISPLAY =====
                st.markdown("---")
                col1, col2, col3 = st.columns([2, 2, 3])

                with col1:
                    c_color = "#10b981" if analysis["classical_score"] >= 70 else "#f59e0b" if analysis["classical_score"] >= 45 else "#dc2626"
                    st.markdown(f"""
                    <div class="grade-box" style="background: linear-gradient(135deg, #0f172a, #1e293b); border-radius: 12px;">
                        <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px;">{t['classical']}</div>
                        <div style="font-size: 4rem; font-weight: 800; color: {c_color};">{analysis['classical_grade']}</div>
                        <div style="font-size: 1rem; color: #94a3b8;">{analysis['classical_score']}/100</div>
                    </div>
                    """, unsafe_allow_html=True)

                with col2:
                    p_color = "#10b981" if analysis["pqc_score"] >= 70 else "#f59e0b" if analysis["pqc_score"] >= 45 else "#dc2626"
                    st.markdown(f"""
                    <div class="grade-box" style="background: linear-gradient(135deg, #0f172a, #1e293b); border-radius: 12px;">
                        <div style="font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px;">{t['pqc']}</div>
                        <div style="font-size: 4rem; font-weight: 800; color: {p_color};">{analysis['pqc_grade']}</div>
                        <div style="font-size: 1rem; color: #94a3b8;">{analysis['pqc_score']}/100</div>
                    </div>
                    """, unsafe_allow_html=True)

                with col3:
                    st.markdown(f"""
                    <div class="metric-box" style="text-align: left; padding: 20px;">
                        <strong>Domain:</strong> {results['domain']}<br>
                        <strong>TLS:</strong> {results['tls_version']}<br>
                        <strong>Cipher:</strong> {results['cipher_suite']['name']}<br>
                        <strong>Key Bits:</strong> {results['cipher_suite']['bits']}<br>
                        <strong>Cert Signature:</strong> {results.get('cert_details', {}).get('sig_algorithm', 'N/A')}<br>
                        <strong>Cert Issuer:</strong> {results['certificate'].get('issuer', 'N/A')}<br>
                        <strong>Valid Until:</strong> {results['certificate'].get('not_after', 'N/A')}
                    </div>
                    """, unsafe_allow_html=True)

                # ===== CDN INFO =====
                cdn_info = results.get("cdn", {})
                if cdn_info.get("detected"):
                    cdn_name = cdn_info.get("provider", "Unknown")
                    cdn_note = cdn_info.get("note", "")
                    if lang_code == "fr":
                        st.warning(f"**CDN détecté : {cdn_name}** -- {cdn_note}. Le support PQC peut provenir du CDN, pas de l'infrastructure de l'organisation.")
                    else:
                        st.warning(f"**CDN detected: {cdn_name}** -- {cdn_note}. PQC support may come from the CDN, not the organization's own infrastructure.")

                # ===== PLAIN-LANGUAGE VERDICT =====
                verdict = generate_verdict(
                    analysis["classical_score"], analysis["pqc_score"],
                    analysis["classical_grade"], analysis["pqc_grade"],
                    lang_code
                )
                verdict_title = "Verdict" if lang_code == "en" else "Verdict"
                st.markdown(f"""
                <div style="background-color: {verdict['color']}15; border-left: 5px solid {verdict['color']}; padding: 16px 20px; border-radius: 6px; margin: 16px 0;">
                    <div style="font-weight: 700; font-size: 1.1rem; color: {verdict['color']}; margin-bottom: 8px;">{verdict_title}</div>
                    <div style="font-size: 0.95rem; color: #333; line-height: 1.6;">{verdict['text']}</div>
                </div>
                """, unsafe_allow_html=True)

                # ===== SHARE CARD =====
                st.markdown("---")
                with st.expander("📤 Share this result"):
                    card = generate_share_card(
                        domain, analysis["classical_grade"], analysis["pqc_grade"],
                        analysis["classical_score"], analysis["pqc_score"]
                    )
                    st.markdown(card, unsafe_allow_html=True)

                    # PNG download button
                    try:
                        png_data = generate_share_card_png(
                            domain, analysis["classical_grade"], analysis["pqc_grade"],
                            analysis["classical_score"], analysis["pqc_score"]
                        )
                        st.download_button(
                            "📷 Download as PNG (LinkedIn-optimized)",
                            png_data,
                            f"pqc_report_{domain}_{datetime.now().strftime('%Y%m%d')}.png",
                            "image/png",
                            key="png_download"
                        )
                    except Exception:
                        st.caption("PNG generation requires Pillow library.")

                    if lang_code == "fr":
                        st.markdown(f"""
                    **Copier pour LinkedIn :**
                    > J'ai explore la maturite cryptographique post-quantique aujourd'hui. Securite classique : {analysis['classical_grade']}. Maturite PQC : {analysis['pqc_grade']}. La transition quantique approche -- voici ce que j'ai appris. https://pqc-scanner.streamlit.app #PQC #Cybersecurite
                    """)
                    else:
                        st.markdown(f"""
                    **Copy for LinkedIn:**
                    > I explored post-quantum cryptography readiness today. Classical security: {analysis['classical_grade']}. PQC readiness: {analysis['pqc_grade']}. The quantum transition is coming -- here's what I learned. https://pqc-scanner.streamlit.app #PQC #Cybersecurity #QuantumComputing
                    """)

                # ===== FINDINGS =====
                st.markdown("---")
                st.markdown("### Detailed Findings")

                for finding in analysis["findings"]:
                    classical = finding.get("classical", "")
                    pqc = finding.get("pqc", "")

                    # Fix 7: Better PQC-via-CDN labeling
                    is_pqc_finding = finding.get("component") == "PQC Hybrid Key Exchange"
                    is_pqc_via_cdn = is_pqc_finding and "via CDN" in pqc
                    is_pqc_native = is_pqc_finding and "PQC-READY" in pqc and "via CDN" not in pqc

                    # Determine CSS class
                    if "CRITICAL" in classical or "CRITICAL" in pqc or "BLOCKED" in pqc:
                        css = "finding-critical"
                        icon = "🔴"
                    elif is_pqc_via_cdn:
                        css = "finding-warning"
                        icon = "⚠️"
                        pqc = "PQC-READY (via CDN)"
                    elif is_pqc_native:
                        css = "finding-safe"
                        icon = "✅"
                        pqc = "PQC-READY (native)"
                    elif "QUANTUM-SAFE" in pqc or "PQC-READY" in pqc:
                        css = "finding-safe"
                        icon = "🟢"
                    elif "QUANTUM-VULNERABLE" in pqc or "NOT DEPLOYED" in pqc or "UPGRADE" in classical or "UPGRADE" in pqc:
                        css = "finding-warning"
                        icon = "🟡"
                    else:
                        css = "finding-info"
                        icon = "🔵"

                    migration_html = f"<br><strong>Migration:</strong> {finding.get('migration', '')}" if finding.get('migration') else ""
                    timeline_html = f"<br><strong>Timeline:</strong> {finding.get('timeline', '')}" if finding.get('timeline') else ""

                    st.markdown(f"""
                    <div class="{css}">
                        <strong>{icon} {finding['component']}</strong>: {finding['value']}<br>
                        <span style="font-size:0.85rem;">Classical: <strong>{classical}</strong> | PQC: <strong>{pqc}</strong></span><br>
                        <em>{finding['detail']}</em>
                        {migration_html}{timeline_html}
                    </div>
                    """, unsafe_allow_html=True)

                # ===== RECOMMENDATIONS =====
                st.markdown("---")
                st.markdown("### Recommendations")
                for i, rec in enumerate(analysis["recommendations"], 1):
                    st.markdown(f"**{i}. [{rec['priority']}]** {rec['action']}\n\n{rec['detail']}")

                # ===== WHAT-IF SIMULATION =====
                whatif_label = "Et si vous upgradiez ?" if lang_code == "fr" else "What if you upgraded?"
                with st.expander(f"🔮 {whatif_label}"):
                    def _score_to_grade(score):
                        if score >= 90: return "A+"
                        if score >= 80: return "A"
                        if score >= 70: return "B"
                        if score >= 60: return "C"
                        if score >= 45: return "D"
                        if score >= 30: return "E"
                        return "F"

                    cur_c = analysis["classical_score"]
                    cur_p = analysis["pqc_score"]
                    cur_cg = analysis["classical_grade"]
                    cur_pg = analysis["pqc_grade"]
                    tls_ver = results.get("tls_version", "")
                    cipher_name_wif = results.get("cipher_suite", {}).get("name", "")
                    pqc_detected_wif = results.get("pqc_probe", {}).get("supported", False)

                    current_label = "Actuel" if lang_code == "fr" else "Current"
                    st.markdown(f"**{current_label}:** {t['classical']} {cur_cg} ({cur_c}) | {t['pqc']} {cur_pg} ({cur_p})")
                    st.markdown("---")

                    simulations = []

                    # Simulate TLS 1.3 upgrade
                    if tls_ver == "TLSv1.2":
                        sim_c = min(100, cur_c + (25 - 15))  # +10 classical
                        sim_p = min(100, cur_p + (20 - 5))    # +15 pqc
                        sim_cg = _score_to_grade(sim_c)
                        sim_pg = _score_to_grade(sim_p)
                        if lang_code == "fr":
                            simulations.append(f"**Si vous passez a TLS 1.3 :** {t['classical']} {cur_cg} ({cur_c}) -> {sim_cg} ({sim_c}) | {t['pqc']} {cur_pg} ({cur_p}) -> {sim_pg} ({sim_p})")
                        else:
                            simulations.append(f"**If you upgrade to TLS 1.3:** {t['classical']} {cur_cg} ({cur_c}) -> {sim_cg} ({sim_c}) | {t['pqc']} {cur_pg} ({cur_p}) -> {sim_pg} ({sim_p})")

                    # Simulate AES-256 upgrade
                    if "AES_128" in cipher_name_wif.upper() or "AES128" in cipher_name_wif.upper():
                        sim_c = min(100, cur_c + (20 - 15))  # +5 classical
                        sim_p = min(100, cur_p + (20 - 10))   # +10 pqc
                        sim_cg = _score_to_grade(sim_c)
                        sim_pg = _score_to_grade(sim_p)
                        if lang_code == "fr":
                            simulations.append(f"**Si vous deployez AES-256 :** {t['classical']} {cur_cg} ({cur_c}) -> {sim_cg} ({sim_c}) | {t['pqc']} {cur_pg} ({cur_p}) -> {sim_pg} ({sim_p})")
                        else:
                            simulations.append(f"**If you deploy AES-256:** {t['classical']} {cur_cg} ({cur_c}) -> {sim_cg} ({sim_c}) | {t['pqc']} {cur_pg} ({cur_p}) -> {sim_pg} ({sim_p})")

                    # Simulate PQC hybrid deployment
                    if not pqc_detected_wif:
                        sim_p = min(100, cur_p + 40)
                        sim_pg = _score_to_grade(sim_p)
                        if lang_code == "fr":
                            simulations.append(f"**Si vous deployez PQC hybride X25519MLKEM768 :** {t['pqc']} {cur_pg} ({cur_p}) -> {sim_pg} ({sim_p})")
                        else:
                            simulations.append(f"**If you deploy PQC hybrid X25519MLKEM768:** {t['pqc']} {cur_pg} ({cur_p}) -> {sim_pg} ({sim_p})")

                    # Combined simulation
                    combined_c = cur_c
                    combined_p = cur_p
                    if tls_ver == "TLSv1.2":
                        combined_c += (25 - 15)
                        combined_p += (20 - 5)
                    if "AES_128" in cipher_name_wif.upper() or "AES128" in cipher_name_wif.upper():
                        combined_c += (20 - 15)
                        combined_p += (20 - 10)
                    if not pqc_detected_wif:
                        combined_p += 40
                    combined_c = min(100, combined_c)
                    combined_p = min(100, combined_p)
                    combined_cg = _score_to_grade(combined_c)
                    combined_pg = _score_to_grade(combined_p)

                    if simulations:
                        for sim in simulations:
                            st.markdown(sim)
                        if len(simulations) > 1:
                            st.markdown("---")
                            if lang_code == "fr":
                                st.markdown(f"**Toutes les upgrades combinées :** {t['classical']} {cur_cg} ({cur_c}) -> {combined_cg} ({combined_c}) | {t['pqc']} {cur_pg} ({cur_p}) -> {combined_pg} ({combined_p})")
                            else:
                                st.markdown(f"**All upgrades combined:** {t['classical']} {cur_cg} ({cur_c}) -> {combined_cg} ({combined_c}) | {t['pqc']} {cur_pg} ({cur_p}) -> {combined_pg} ({combined_p})")
                    else:
                        if lang_code == "fr":
                            st.markdown("Votre configuration est deja optimale pour les composants mesures. Verifiez les certificats PQC (ML-DSA) lorsqu'ils seront disponibles.")
                        else:
                            st.markdown("Your configuration is already optimal for the measured components. Check for PQC certificates (ML-DSA) when they become available.")

                # ===== DOWNLOAD =====
                st.markdown("---")
                report = {
                    "scan_results": results,
                    "analysis": {
                        "classical_score": analysis["classical_score"],
                        "classical_grade": analysis["classical_grade"],
                        "pqc_score": analysis["pqc_score"],
                        "pqc_grade": analysis["pqc_grade"],
                        "findings": analysis["findings"],
                        "recommendations": analysis["recommendations"]
                    }
                }
                dl_col1, dl_col2 = st.columns(2)
                with dl_col1:
                    st.download_button(
                        "📥 Download Full Report (JSON)",
                        json.dumps(report, indent=2, default=str),
                        f"pqc_scan_{domain}_{datetime.now().strftime('%Y%m%d')}.json",
                        "application/json",
                        key="json_download"
                    )
                with dl_col2:
                    exec_summary = generate_executive_summary_txt(domain, results, analysis)
                    st.download_button(
                        "📄 Download Executive Summary (TXT)",
                        exec_summary,
                        f"pqc_summary_{domain}_{datetime.now().strftime('%Y%m%d')}.txt",
                        "text/plain",
                        key="txt_download"
                    )

# ===== TAB 2: HNDL =====
with tab2:
    if lang_code == "fr":
        st.markdown("### Évaluation du Risque « Récolter Maintenant, Déchiffrer Plus Tard » (HNDL)")
        st.markdown("""
        Des acteurs étatiques **enregistrent le trafic chiffré aujourd'hui** pour le déchiffrer
        lorsque les ordinateurs quantiques seront disponibles.
        Si vos données doivent rester confidentielles au-delà de 2030, vous êtes en danger **dès maintenant**.
        """)
    else:
        st.markdown("### Harvest Now, Decrypt Later (HNDL) Risk Assessment")
        st.markdown("""
        Nation-state actors are **recording encrypted traffic today** to decrypt when quantum computers arrive.
        If your data must remain confidential beyond 2030, you are at risk **right now**.
        """)

    sector_label = "Sélectionnez votre secteur d'activité :" if lang_code == "fr" else "Select your industry sector:"
    selected_sector = st.selectbox(sector_label, list(HARVEST_NOW_SECTORS.keys()))
    sector = HARVEST_NOW_SECTORS[selected_sector]
    risk_color = "#dc2626" if "VERY HIGH" in sector["risk"] else "#f59e0b" if "HIGH" in sector["risk"] else "#3b82f6"

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f'<div class="metric-box"><div style="font-size:1.5rem;color:{risk_color};">{sector["risk"]}</div><div>HNDL Risk</div></div>', unsafe_allow_html=True)
    with col2:
        st.markdown(f'<div class="metric-box"><div style="font-size:1.5rem;">{sector["data_lifetime"]}</div><div>Data Lifetime</div></div>', unsafe_allow_html=True)
    with col3:
        st.markdown('<div class="metric-box"><div style="font-size:1.5rem;">5-15 years</div><div>Est. Time to CRQC</div></div>', unsafe_allow_html=True)
    st.markdown(f"**Data at risk:** {sector['note']}")

    st.markdown("---")
    if lang_code == "fr":
        st.markdown("### Calendrier de la Menace Quantique")
        st.markdown("""
        | Année | Jalon |
        |-------|-------|
        | **2024** | Le NIST publie les premiers standards PQC (FIPS 203, 204, 205) |
        | **2025-2026** | L'ANSSI, le BSI et la NSA publient des guides de migration. Chrome/Cloudflare déploient le PQC hybride. |
        | **2027-2028** | Entrée en vigueur du Cyber Resilience Act européen |
        | **2030** | Date limite NSA : les systèmes de sécurité nationale doivent être PQC-ready |
        | **2030-2035** | Estimations majoritaires pour les ordinateurs quantiques cryptographiquement pertinents |
        """)
    else:
        st.markdown("### Quantum Threat Timeline")
        st.markdown("""
        | Year | Milestone |
        |------|-----------|
        | **2024** | NIST publishes first PQC standards (FIPS 203, 204, 205) |
        | **2025-2026** | ANSSI, BSI, NSA issue migration guidance. Chrome/Cloudflare deploy PQC hybrid. |
        | **2027-2028** | EU Cyber Resilience Act enforcement begins |
        | **2030** | NSA deadline: national security systems must be PQC-ready |
        | **2030-2035** | Most estimates for cryptographically relevant quantum computers |
        """)


# ===== TAB CAC40 =====
with tab_cac:
    # Rescan button
    rescan_col1, rescan_col2 = st.columns([3, 1])
    with rescan_col2:
        rescan_btn = st.button("🔄 Rescan CAC40" if lang_code == "en" else "🔄 Rescanner le CAC 40", use_container_width=True)

    if rescan_btn:
        from scan_cac40 import CAC40_DOMAINS
        progress = st.progress(0, text="Scanning CAC40...")
        fresh_results = []
        for i, (name, dom) in enumerate(CAC40_DOMAINS):
            progress.progress((i+1)/len(CAC40_DOMAINS), text=f"Scanning {name} ({dom})...")
            # Use main app's scan + probe (proven working)
            scan_res = scan_domain(dom)
            if scan_res.get("error"):
                fresh_results.append({"name": name, "domain": dom, "error": scan_res["error"]})
            else:
                analysis_res = analyze_pqc_readiness(scan_res)
                entry = {
                    "name": name, "domain": dom,
                    "tls": scan_res.get("tls_version", ""),
                    "cipher": scan_res.get("cipher_suite", {}).get("name", ""),
                    "bits": scan_res.get("cipher_suite", {}).get("bits", 0),
                    "classical_score": analysis_res["classical_score"],
                    "classical_grade": analysis_res["classical_grade"],
                    "pqc_score": analysis_res["pqc_score"],
                    "pqc_grade": analysis_res["pqc_grade"],
                    "scan_date": datetime.now().strftime("%Y-%m-%d"),
                }
                # Check if PQC was detected
                pqc_probe = scan_res.get("pqc_probe", {})
                if pqc_probe.get("supported"):
                    entry["pqc_hybrid"] = pqc_probe.get("group", "X25519MLKEM768")
                # CDN info
                cdn_info = scan_res.get("cdn", {})
                if cdn_info.get("detected"):
                    entry["cdn"] = cdn_info.get("provider", "Unknown")
                    if entry.get("pqc_hybrid"):
                        entry["pqc_via_cdn"] = True
                fresh_results.append(entry)
        progress.empty()
        save_path = Path(__file__).parent / "cac40_results.json"
        with open(save_path, "w") as f:
            json.dump(fresh_results, f, indent=2)
        ok = len([r for r in fresh_results if not r.get("error")])
        pqc = len([r for r in fresh_results if r.get("pqc_hybrid")])
        st.success(f"Scan complete: {ok}/40 | PQC hybrid detected: {pqc}/40")
        st.rerun()

    cac40 = load_cac40_data()
    successful = [r for r in cac40 if not r.get("error")]

    if not successful:
        st.warning("No CAC40 data yet. Click 'Rescan CAC40' to run the first scan." if lang_code == "en" else "Pas encore de données CAC 40. Cliquez sur 'Rescanner le CAC 40' pour lancer le premier scan.")
    else:
        pqc_ready = sum(1 for r in successful if r.get("pqc_hybrid"))
        pqc_via_cdn = sum(1 for r in successful if r.get("pqc_hybrid") and r.get("cdn"))
        pqc_native = pqc_ready - pqc_via_cdn
        cdn_count = sum(1 for r in successful if r.get("cdn"))
        tls12_count = sum(1 for r in successful if r.get('tls','')=='TLSv1.2')
        aes128_count = sum(1 for r in successful if '128' in r.get('cipher',''))
        avg_pqc = sum(r.get('pqc_score',0) for r in successful)//len(successful)
        avg_cls = sum(r.get('classical_score',0) for r in successful)//len(successful)
        scan_date = successful[0].get("scan_date", "N/A") if successful else "N/A"

        if lang_code == "fr":
            st.markdown("### Maturité PQC du CAC 40")
            st.markdown(f"""
            **{len(successful)} entreprises du CAC 40 scannées** | Dernier scan : {scan_date}

            | Indicateur | Résultat | Explication |
            |-----------|----------|-------------|
            | PQC hybride détecté (total) | **{pqc_ready}/{len(successful)} ({pqc_ready*100//len(successful)}%)** | Testé via handshake TLS avec X25519MLKEM768 |
            | ↳ PQC via CDN | **{pqc_via_cdn}** | PQC fourni par le CDN (Cloudflare, AWS), pas par l'organisation |
            | ↳ PQC potentiellement natif | **{pqc_native}** | Pas de CDN détecté -- déploiement potentiellement propre |
            | Derrière un CDN | **{cdn_count}/{len(successful)}** | CDN détecté via émetteur du certificat et en-têtes HTTP |
            | Score PQC moyen | **{avg_pqc}/100** | 0-100. >60 = PQC hybride actif. <45 = pas de PQC |
            | Score classique moyen | **{avg_cls}/100** | TLS + chiffrement + échange de clés + certificat |
            | Encore sur TLS 1.2 | **{tls12_count}/{len(successful)}** | TLS 1.3 requis pour la migration PQC |
            | Utilisant AES-128 | **{aes128_count}/{len(successful)}** | AES-256 recommandé pour la sécurité post-quantique |

            **{pqc_native} entreprise(s) semblent avoir déployé le PQC de manière native** (sans CDN intermédiaire).
            **{pqc_via_cdn} entreprise(s) bénéficient du PQC via leur CDN** (Cloudflare, AWS CloudFront).
            **{len(successful)-pqc_ready} entreprise(s) n'ont aucun support PQC détecté** et sont exposées au risque « Récolter Maintenant, Déchiffrer Plus Tard ».

            > ⚠️ **PQC via CDN ≠ maturité PQC organisationnelle.** Le PQC hybride détecté via un CDN protège le trafic edge-to-client, mais l'infrastructure interne de l'organisation peut ne pas être prête pour le PQC.

            > ⚠️ Les résultats peuvent varier entre les scans. Les sites derrière un CDN redirigent le trafic vers différents serveurs de bordure, dont certains supportent le PQC et d'autres non. Les scores sont mis en cache pendant 1 heure pour assurer la cohérence.
            """)

            with st.expander("📋 Méthodologie"):
                st.markdown("""
                **Comment ce scan fonctionne :**
                1. Connexion TLS au domaine public de chaque entreprise (port 443)
                2. Analyse du protocole TLS, suite de chiffrement, algorithme de signature du certificat
                3. Sonde PQC : tentative de handshake TLS avec le groupe X25519MLKEM768 via OpenSSL 3.5+
                4. Détection CDN : vérification de l'émetteur du certificat et des en-têtes HTTP (Server, Via)
                5. Scoring dual : Sécurité Classique (0-100) + Maturité PQC (0-100)

                **Limites :** Ce scan ne mesure que la façade web publique. L'infrastructure interne (VPN, API, bases de données)
                n'est pas mesurable par un scan externe.
                """)
        else:
            st.markdown("### CAC 40 PQC Readiness")
            st.markdown(f"""
            **{len(successful)} CAC 40 companies scanned** | Last scan: {scan_date}

            | Metric | Result | Note |
            |--------|--------|------|
            | PQC hybrid detected (total) | **{pqc_ready}/{len(successful)} ({pqc_ready*100//len(successful)}%)** | Tested via TLS handshake with X25519MLKEM768 |
            | ↳ PQC via CDN | **{pqc_via_cdn}** | PQC provided by CDN (Cloudflare, AWS), not the organization |
            | ↳ PQC potentially native | **{pqc_native}** | No CDN detected -- may be genuine organizational deployment |
            | Behind a CDN | **{cdn_count}/{len(successful)}** | CDN detected via certificate issuer and HTTP headers |
            | Average PQC score | **{avg_pqc}/100** | 0-100 scale. >60 = PQC hybrid active. <45 = no PQC deployed |
            | Average classical score | **{avg_cls}/100** | TLS version + cipher + key exchange + certificate strength |
            | Still on TLS 1.2 | **{tls12_count}/{len(successful)}** | TLS 1.3 required for PQC migration |
            | Using AES-128 | **{aes128_count}/{len(successful)}** | AES-256 recommended for post-quantum symmetric security |

            **{pqc_native} companies appear to have deployed PQC natively** (no CDN intermediary).
            **{pqc_via_cdn} companies benefit from PQC via their CDN** (Cloudflare, AWS CloudFront).
            **{len(successful)-pqc_ready} companies have no PQC support detected** and are exposed to "Harvest Now, Decrypt Later" risk.

            > ⚠️ **PQC via CDN ≠ organizational PQC readiness.** PQC hybrid detected via a CDN protects edge-to-client traffic, but the organization's internal infrastructure may not be PQC-ready.

            > ⚠️ Results may vary between scans. CDN-based sites route traffic through different edge servers, some of which may support PQC while others do not. Scores are cached for 1 hour to ensure consistency.
            """)

            with st.expander("📋 Methodology"):
                st.markdown("""
                **How this scan works:**
                1. TLS connection to each company's public domain (port 443)
                2. Analysis of TLS protocol, cipher suite, certificate signature algorithm
                3. PQC probe: TLS handshake attempt with X25519MLKEM768 group via OpenSSL 3.5+
                4. CDN detection: certificate issuer and HTTP header check (Server, Via)
                5. Dual scoring: Classical Security (0-100) + PQC Readiness (0-100)

                **Limitations:** This scan only measures the public web frontend. Internal infrastructure (VPNs, APIs, databases)
                cannot be measured by an external scan.
                """)

    st.markdown("---")

    # Leaderboard (password-protected)
    if lang_code == "fr":
        leaderboard_label = "🔒 Classement détaillé par entreprise (accès restreint)"
    else:
        leaderboard_label = "🔒 Detailed company leaderboard (restricted access)"

    pwd = st.text_input(leaderboard_label, type="password", placeholder="Enter access code")
    import hashlib
    pwd_hash = hashlib.sha256(pwd.encode()).hexdigest() if pwd else ""
    try:
        expected_hash = os.environ.get("LEADERBOARD_HASH", st.secrets.get("leaderboard_hash", "35b00fd8bb3532c0b14954de0e5aaf23dbf1d7f0cb3db391360ec39105449268"))
    except Exception:
        expected_hash = os.environ.get("LEADERBOARD_HASH", "35b00fd8bb3532c0b14954de0e5aaf23dbf1d7f0cb3db391360ec39105449268")
    if pwd_hash == expected_hash:
        if lang_code == "fr":
            st.markdown("### Classement par Maturité PQC")
        else:
            st.markdown("### Leaderboard by PQC Readiness")

        sorted_cac = sorted(successful, key=lambda x: (-x.get("pqc_score", 0), -x.get("classical_score", 0)))

        header_cls = "Classique" if lang_code == "fr" else "Classical"
        header_pqc = "PQC"
        header_cdn = "CDN"
        header_pqc_hybrid = "PQC Hybride" if lang_code == "fr" else "PQC Hybrid"

        table_md = f"| # | Entreprise | {header_cls} | {header_pqc} | {header_pqc_hybrid} | {header_cdn} | TLS |\n"
        table_md += "|---|-----------|----------|-----|------------|-----|-----|\n"
        for i, r in enumerate(sorted_cac, 1):
            c_grade = r.get("classical_grade", "?")
            p_grade = r.get("pqc_grade", "?")
            pqc_hybrid = r.get("pqc_hybrid", "")
            cdn = r.get("cdn", "")
            pqc_display = f"✅ {pqc_hybrid}" if pqc_hybrid else "❌"
            cdn_display = cdn if cdn else "—"
            if pqc_hybrid and cdn:
                pqc_display = f"⚠️ {pqc_hybrid}"
            table_md += f"| {i} | {r['name']} | **{c_grade}** ({r.get('classical_score',0)}) | **{p_grade}** ({r.get('pqc_score',0)}) | {pqc_display} | {cdn_display} | {r.get('tls','?')} |\n"

        st.markdown(table_md)

        if lang_code == "fr":
            st.markdown("""
            > ⚠️ **Note CDN** : Le support PQC hybride détecté sur le site web public peut être fourni par le CDN (Cloudflare, Akamai, AWS CloudFront)
            > et non par l'infrastructure propre de l'organisation. La maturité PQC réelle d'une organisation inclut ses services internes,
            > VPN, API et bases de données -- qui ne sont pas mesurables par un scan externe.
            """)
        else:
            st.markdown("""
            > ⚠️ **CDN Note**: PQC hybrid support detected on the public website may be provided by the CDN (Cloudflare, Akamai, AWS CloudFront)
            > rather than the organization's own infrastructure. True organizational PQC readiness includes internal services,
            > VPNs, APIs, and databases -- which cannot be measured by an external scan.
            """)

    elif pwd and pwd_hash != expected_hash:
        if lang_code == "fr":
            st.error("Code d'accès incorrect.")
        else:
            st.error("Incorrect access code.")

    st.markdown("---")
    if lang_code == "fr":
        st.caption("Scan réalisé par le PQC Readiness Scanner. Les scores PQC peuvent être sous-estimés en raison des limitations de détection (voir FAQ).")
    else:
        st.caption("Scan performed by PQC Readiness Scanner. PQC scores may be underestimated due to detection limitations (see FAQ).")


# ===== TAB 3: CLOUD MIGRATION GUIDES =====
with tab3:
    if lang_code == "fr":
        st.markdown("### Guides de Migration PQC par Fournisseur Cloud")
        st.markdown("Configurations spécifiques pour activer le PQC sur les principales plateformes cloud.")
        cloud_label = "Sélectionnez votre fournisseur cloud :"
    else:
        st.markdown("### Cloud Provider PQC Migration Guides")
        st.markdown("Specific configuration guidance for enabling PQC on major cloud platforms.")
        cloud_label = "Select your cloud provider:"

    cloud = st.selectbox(cloud_label, ["AWS", "Microsoft Azure", "Google Cloud (GCP)", "Cloudflare"])

    if cloud == "AWS":
        st.markdown("""
        #### AWS PQC Migration Guide

        **Current PQC Support:**
        - **AWS KMS**: Supports PQC key agreement (ML-KEM) for envelope encryption since 2024
        - **s2n-tls**: AWS's TLS library supports hybrid PQC key exchange (X25519+Kyber)
        - **AWS Certificate Manager**: PQC certificates not yet supported

        **Enable PQC Hybrid on AWS:**

        ```bash
        # For applications using s2n-tls (AWS SDK, Lambda, etc.)
        # Set security policy to support PQC
        aws elbv2 modify-listener \\
          --listener-arn <arn> \\
          --ssl-policy ELBSecurityPolicy-TLS13-1-3-2024-PQ

        # For CloudFront distributions
        aws cloudfront update-distribution \\
          --id <dist-id> \\
          --viewer-certificate MinimumProtocolVersion=TLSv1.3_2024_PQ
        ```

        **AWS KMS with PQC:**
        ```python
        import boto3
        kms = boto3.client('kms')
        # KMS automatically uses PQC-safe key wrapping
        # when using the latest AWS SDK versions
        response = kms.generate_data_key(
            KeyId='alias/my-key',
            KeySpec='AES_256'  # Symmetric key is quantum-safe
        )
        ```

        **Priority Actions:**
        1. Upgrade to latest AWS SDK (PQC hybrid enabled by default)
        2. Set TLS 1.3 security policies on all load balancers
        3. Use AES-256 (not AES-128) for all S3/EBS/RDS encryption
        4. Monitor AWS Security Blog for PQC certificate support
        """)

    elif cloud == "Microsoft Azure":
        st.markdown("""
        #### Microsoft Azure PQC Migration Guide

        **Current PQC Support:**
        - **Azure Key Vault**: PQC key types under preview
        - **Azure TLS**: TLS 1.3 supported on App Gateway, Front Door
        - **SymCrypt**: Microsoft's crypto library supports ML-KEM

        **Enable TLS 1.3 on Azure:**
        ```bash
        # Azure Application Gateway
        az network application-gateway ssl-policy set \\
          --resource-group <rg> \\
          --gateway-name <gw> \\
          --policy-type Predefined \\
          --policy-name AppGwSslPolicy20230202

        # Azure Front Door
        az afd custom-domain update \\
          --custom-domain-name <domain> \\
          --minimum-tls-version TLS13
        ```

        **Priority Actions:**
        1. Enable TLS 1.3 on all Azure Front Door and App Gateway instances
        2. Use Azure Key Vault with RSA-4096 or EC P-384 (best classical, easier PQC migration)
        3. Monitor Microsoft Security Response Center for PQC updates
        4. Test SymCrypt PQC preview in non-production environments
        """)

    elif cloud == "Google Cloud (GCP)":
        st.markdown("""
        #### Google Cloud PQC Migration Guide

        **Current PQC Support:**
        - **Google Cloud TLS**: X25519+Kyber768 hybrid enabled by default on many services
        - **Cloud KMS**: Investigating PQC key types
        - **Certificate Authority Service**: PQC certificates not yet available
        - **Chrome**: Supports X25519Kyber768 since Chrome 124

        **GCP is the most PQC-advanced cloud provider.**

        ```bash
        # Google Cloud Load Balancer
        # TLS 1.3 with PQC hybrid is enabled by default
        # on modern HTTPS load balancers

        # Verify PQC support
        gcloud compute ssl-policies describe <policy-name> \\
          --format="json(minTlsVersion,profile,customFeatures)"

        # Create a TLS 1.3-only policy
        gcloud compute ssl-policies create pqc-ready-policy \\
          --profile=MODERN \\
          --min-tls-version=1.2
        ```

        **Priority Actions:**
        1. Use MODERN SSL policy profile (enables TLS 1.3 with PQC hybrid)
        2. Ensure clients support Kyber (Chrome 124+, BoringSSL)
        3. Use AES-256-GCM for all Cloud Storage and BigQuery encryption
        4. Monitor Google Cloud Security Blog for PQC certificate availability
        """)

    elif cloud == "Cloudflare":
        st.markdown("""
        #### Cloudflare PQC Migration Guide

        **Current PQC Support:**
        - **PQC hybrid key exchange**: X25519Kyber768Draft00 enabled by default since October 2024
        - **All Cloudflare zones**: PQC hybrid is automatic -- no configuration needed
        - **Cloudflare Tunnel**: Supports PQC key exchange

        **Cloudflare is the easiest path to PQC.**

        If your site is behind Cloudflare, your visitors using Chrome 124+ or Firefox 128+ are already getting PQC hybrid key exchange automatically.

        **Verify PQC is active:**
        ```bash
        # Test with curl (requires PQC-capable OpenSSL)
        curl -v --curves X25519Kyber768Draft00 https://yourdomain.com 2>&1 | grep "Server Temp Key"

        # Or check in Chrome DevTools:
        # Security tab > Connection > Key Exchange Group
        # Should show "X25519Kyber768Draft00"
        ```

        **Priority Actions:**
        1. Ensure Cloudflare proxy is enabled (orange cloud) for all DNS records
        2. Set minimum TLS version to 1.2 (Settings > SSL/TLS > Edge Certificates)
        3. Enable TLS 1.3 (Settings > SSL/TLS > Edge Certificates)
        4. PQC hybrid is automatic -- no further action needed for key exchange
        5. Certificate signatures remain RSA/ECDSA -- monitor Cloudflare blog for PQC cert support
        """)


# ===== TAB 5: PQC REFERENCE =====
with tab5:
    if lang_code == "fr":
        st.markdown("### Standards NIST de Cryptographie Post-Quantique")
    else:
        st.markdown("### NIST Post-Quantum Cryptography Standards")
    st.markdown("""
    | Standard | Algorithm | Purpose | Based On |
    |----------|-----------|---------|----------|
    | **FIPS 203** | ML-KEM (CRYSTALS-Kyber) | Key Encapsulation | Lattice-based |
    | **FIPS 204** | ML-DSA (CRYSTALS-Dilithium) | Digital Signatures | Lattice-based |
    | **FIPS 205** | SLH-DSA (SPHINCS+) | Digital Signatures | Hash-based |
    """)

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        title_vuln = "#### 🔴 Vulnérables au Quantique" if lang_code == "fr" else "#### 🔴 Quantum-Vulnerable"
        st.markdown(title_vuln)
        st.markdown("""
        | Algorithme | Attaque Quantique |
        |-----------|----------------|
        | RSA | Shor |
        | ECDSA / ECDH | Shor (ECDLP) |
        | DSA / DH | Shor |
        | AES-128 | Grover (64-bit effectif) |
        """)
    with col2:
        title_safe = "#### 🟢 Résistants au Quantique" if lang_code == "fr" else "#### 🟢 Quantum-Safe"
        st.markdown(title_safe)
        st.markdown("""
        | Algorithme | Notes |
        |-----------|-------|
        | AES-256 | 128-bit effectif post-quantique |
        | ChaCha20 | Cle symetrique 256-bit |
        | SHA-256/384/3 | Resistance adequate |
        | ML-KEM (Kyber) | NIST FIPS 203 |
        | ML-DSA (Dilithium) | NIST FIPS 204 |
        | SLH-DSA (SPHINCS+) | NIST FIPS 205 |
        """)

    st.markdown("---")
    if lang_code == "fr":
        st.markdown("### Stratégie de Migration")
        st.markdown("""
        1. **Inventaire** -- Cartographier toutes les dépendances cryptographiques
        2. **Prioriser** -- Données à longue durée de vie et cibles à haute valeur en premier
        3. **Moderniser le classique** -- TLS 1.3, AES-256, ECDHE partout
        4. **Hybride d'abord** -- Déployer X25519+ML-KEM-768 pour l'échange de clés
        5. **Certificats PQC** -- Quand les AC supporteront les certificats ML-DSA
        6. **Surveiller** -- Suivre les avancées de l'informatique quantique et ajuster
        """)
    else:
        st.markdown("### Migration Strategy")
        st.markdown("""
        1. **Inventory** -- Map all cryptographic dependencies
        2. **Prioritize** -- Long-lived data and high-value targets first
        3. **Upgrade classical** -- TLS 1.3, AES-256, ECDHE everywhere
        4. **Hybrid first** -- Deploy X25519+ML-KEM-768 for key exchange
        5. **PQC certificates** -- When CAs support ML-DSA certificates
        6. **Monitor** -- Track quantum computing advances and adjust
        """)


# ===== TAB 6: FAQ =====
with tab6:
    if lang_code == "fr":
        st.markdown("### Questions Fréquentes")

        st.markdown("#### Comment fonctionne la détection PQC hybride ?")
        st.markdown(f"""
        Le scanner utilise deux méthodes de détection :

        1. **Sonde OpenSSL PQC** (principale) : Le serveur utilise **{OPENSSL_INFO['version']}**.
        {"Cette version **supporte les groupes PQC** (ML-KEM/Kyber). Le scanner teste activement les serveurs en tentant des handshakes TLS avec des groupes d'échange de clés PQC (X25519+ML-KEM-768 et variantes)." if OPENSSL_INFO['pqc_capable'] else "Cette version **ne supporte pas** les algorithmes PQC. La détection est limitée."}

        2. **Analyse des suites de chiffrement** (secondaire) : Vérifie les suites négociées et les clés temporaires du serveur.

        {"**Ce scanner peut détecter de manière fiable le support PQC hybride.**" if OPENSSL_INFO['pqc_capable'] else "**Impact :** Les scores PQC peuvent être sous-estimés. « NON DÉTECTÉ » peut signifier que le scanner ne peut pas tester, pas que le serveur ne supporte pas le PQC."}
        """)

        st.markdown("#### Pourquoi la plupart des sites ont-ils un score PQC faible ?")
        st.markdown("""
        C'est normal. En avril 2026, **moins de 5% des serveurs** dans le monde supportent l'échange
        de clés PQC hybride. Les certificats PQC (ML-DSA) ne sont pas encore disponibles
        auprès des autorités de certification commerciales.

        Le score PQC mesure la **maturité de migration**, pas un échec. Un score de 35/100
        signifie « bonne base classique, migration PQC à planifier ». Un score de 15/100 signifie
        « cryptographie obsolète, vulnérabilités classiques ET quantiques ».
        """)

        st.markdown("#### Quelle est la différence entre les deux scores ?")
        st.markdown("""
        - **Sécurité Classique (A-F)** : Évalue la robustesse de votre cryptographie contre les
          menaces actuelles. TLS 1.3, AES-256, ECDHE = bon score classique.
        - **Maturité PQC (A-F)** : Évalue votre préparation à la menace quantique.
          Même avec un A en sécurité classique, vous pouvez avoir un F en PQC si vous n'avez
          pas commencé la migration.

        **L'écart entre les deux scores = votre risque « Récolter Maintenant, Déchiffrer Plus Tard ».**
        """)

        st.markdown("#### Ce scanner est-il conforme aux recommandations de l'ANSSI ?")
        st.markdown("""
        Le scanner s'aligne sur les recommandations de l'ANSSI pour la migration PQC (2024) :
        - Inventaire cryptographique
        - Priorisation des données à longue durée de confidentialité
        - Migration hybride (classique + PQC) avant migration complète
        - Suivi des standards NIST FIPS 203/204/205

        Les références réglementaires incluent NIS2 (Art. 21), DORA (Art. 11),
        et les futures exigences du Cyber Resilience Act européen.
        """)

        st.markdown("#### Les donnees scannees sont-elles stockees ?")
        st.markdown("""
        Seuls le nom de domaine, le score et la date sont stockés localement pour afficher
        les scans récents. **Aucune donnée de certificat ni de configuration TLS n'est conservée.**
        Le scan est équivalent à une connexion HTTPS normale -- il ne révèle rien qui ne soit
        pas déjà public.
        """)

        st.markdown("#### Comment le score est-il calcule ?")
        st.markdown("""
        | Composant | Points Classique | Points PQC | Justification |
        |-----------|-----------------|------------|---------------|
        | TLS 1.3 | +25 | +20 | Requis pour PQC hybride |
        | TLS 1.2 | +15 | +5 | Ne supporte pas le PQC |
        | Echange de cles ECDHE | +25 | +10 | Meilleur classique, vulnerable au quantique |
        | AES-256 / ChaCha20 | +20 | +20 | Symetrique quantum-safe |
        | AES-128 | +15 | +10 | Reduit par Grover |
        | Certificat ECDSA | +20 | +5 | Meilleure signature classique |
        | Certificat RSA | +15 | +3 | Vulnerable au quantique |
        | SHA-384/256 | +10 | +5 | Hash quantum-safe |
        | PQC hybride detecte | -- | +40 | Protection post-quantique active |
        | **Max possible** | **100** | **100** | |
        """)

        st.markdown("#### Qui a construit cet outil ?")
        st.markdown("""
        **Amin Hasbini** -- AI & Cybersecurity Strategy Executive.
        12 ans chez Kaspersky GReAT (directeur du centre de recherche META, 70 pays).
        Contributeur aux travaux de l'OPECST au Sénat français sur les risques IA.
        Membre de Renaissance Numérique. Basé à Paris.

        [LinkedIn](https://www.linkedin.com/in/amin-hasbini-cybersecurity/)
        """)

    else:
        st.markdown("### Frequently Asked Questions")

        st.markdown("#### How does PQC hybrid detection work?")
        st.markdown(f"""
        The scanner uses two methods to detect PQC support:

        1. **OpenSSL PQC probe** (primary): The server runs **{OPENSSL_INFO['version']}**.
        {"This version **supports PQC groups** (ML-KEM/Kyber). The scanner actively probes servers by attempting TLS handshakes with PQC key exchange groups (X25519+ML-KEM-768 and variants)." if OPENSSL_INFO['pqc_capable'] else "This version **does not support** PQC algorithms. Detection is limited."}

        2. **Cipher suite analysis** (fallback): Checks negotiated cipher suites and server temp keys for PQC indicators.

        {"**This scanner can reliably detect PQC hybrid support.**" if OPENSSL_INFO['pqc_capable'] else "**Impact:** PQC scores may be underestimated. 'NOT DETECTED' may mean the scanner cannot test, not that the server doesn't support PQC."}
        """)

        st.markdown("#### Why do all sites have a low PQC score?")
        st.markdown("""
        This is expected. As of April 2026, **fewer than 5% of servers** worldwide support
        PQC hybrid key exchange. PQC certificates (ML-DSA) are not yet available
        from commercial certificate authorities.

        The PQC score measures **migration readiness**, not failure. A score of 35/100
        means "good classical foundation, PQC migration to be planned." A score of 15/100
        means "outdated cryptography, vulnerable to both classical AND quantum attacks."
        """)

        st.markdown("#### What is the difference between the two scores?")
        st.markdown("""
        - **Classical Security (A-F)**: Evaluates your cryptographic strength against today's
          threats. TLS 1.3, AES-256, ECDHE = good classical score.
        - **PQC Readiness (A-F)**: Evaluates your preparation for the quantum threat.
          Even with an A in classical security, you can have an F in PQC if you haven't
          started the migration.

        **The gap between the two scores = your "Harvest Now, Decrypt Later" risk.**
        """)

        st.markdown("#### Is this scanner aligned with ANSSI recommendations?")
        st.markdown("""
        The scanner aligns with ANSSI's PQC migration guidance (2024):
        - Cryptographic inventory
        - Prioritization of long-lived confidential data
        - Hybrid migration (classical + PQC) before full migration
        - Alignment with NIST FIPS 203/204/205

        Regulatory references include NIS2 (Art. 21), DORA (Art. 11),
        and the upcoming EU Cyber Resilience Act requirements.
        """)

        st.markdown("#### Is scan data stored?")
        st.markdown("""
        Only the domain name, score, and date are stored locally to display recent scans.
        **No certificate data or TLS configuration is retained.** The scan is equivalent to
        a normal HTTPS connection -- it reveals nothing that isn't already public.
        """)

        st.markdown("#### How is the score calculated?")
        st.markdown("""
        | Component | Classical Points | PQC Points | Rationale |
        |-----------|-----------------|------------|-----------|
        | TLS 1.3 | +25 | +20 | Required for PQC hybrid |
        | TLS 1.2 | +15 | +5 | Cannot support PQC |
        | ECDHE key exchange | +25 | +10 | Best classical, quantum-vulnerable |
        | AES-256 / ChaCha20 | +20 | +20 | Quantum-safe symmetric |
        | AES-128 | +15 | +10 | Reduced by Grover's |
        | ECDSA certificate | +20 | +5 | Best classical signature |
        | RSA certificate | +15 | +3 | Quantum-vulnerable |
        | SHA-384/256 | +10 | +5 | Quantum-safe hash |
        | PQC hybrid detected | -- | +40 | Active post-quantum protection |
        | **Max possible** | **100** | **100** | |
        """)

        st.markdown("#### Who built this tool?")
        st.markdown("""
        **Amin Hasbini** -- AI & Cybersecurity Strategy Executive.
        12 years at Kaspersky GReAT (Director of META Research Center, 70 countries).
        Contributor to the French Senate (OPECST) on AI risk.
        Member of Renaissance Numerique. Based in Paris.

        [LinkedIn](https://www.linkedin.com/in/amin-hasbini-cybersecurity/)
        """)


# Email signup via Formspree embedded form
st.markdown("---")
if lang_code == "fr":
    st.markdown("### Restez informé sur la transition PQC")
    st.markdown("Recevez les mises à jour sur les standards PQC, les évolutions du CAC 40, et les guides de migration.")
else:
    st.markdown("### Stay informed on the PQC transition")
    st.markdown("Get updates on PQC standards, CAC 40 evolution, and migration guides.")

placeholder_text = "Votre adresse email" if lang_code == "fr" else "Your email address"
btn_text = "S'inscrire" if lang_code == "fr" else "Subscribe"
st.markdown(f"""
<form action="https://formspree.io/f/xzdklvoa" method="POST" target="_blank" style="display:flex;gap:8px;max-width:500px;">
    <input type="email" name="email" placeholder="{placeholder_text}" required
        style="flex:1;padding:10px 14px;border:1px solid #d1d5db;border-radius:6px;font-size:0.95rem;outline:none;">
    <button type="submit"
        style="padding:10px 20px;background:#1e293b;color:white;border:none;border-radius:6px;font-size:0.95rem;cursor:pointer;">
        📧 {btn_text}
    </button>
</form>
""", unsafe_allow_html=True)

# Footer
st.markdown("""
<div class="footer">
    <strong>PQC Readiness Scanner v4.1</strong> | Built by Amin Hasbini |
    <a href="https://www.linkedin.com/in/amin-hasbini-cybersecurity/">LinkedIn</a> |
    AI & Cybersecurity Strategy Executive<br>
    Sources: NIST FIPS 203/204/205, ANSSI PQC Guidance, WEF Global Cybersecurity Outlook 2025
</div>
""", unsafe_allow_html=True)
