"""
CyberRecon Web Suite - Flask Backend
=====================================
A cybersecurity reconnaissance toolkit API.
All endpoints accept JSON and return JSON responses.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import socket
import ssl
import dns.resolver
import whois
import concurrent.futures
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Allow all origins so your HTML frontend can connect

# ─────────────────────────────────────────
# HELPER: Standard JSON response builder
# ─────────────────────────────────────────
def success(data):
    return jsonify({"status": "success", "data": data})

def error(msg, code=400):
    return jsonify({"status": "error", "message": msg}), code


# ─────────────────────────────────────────
# 1. SUBDOMAIN SCANNER
#    POST /api/subdomain-scan
#    Input:  { "domain": "example.com" }
#    Output: List of subdomains with resolved IPs
# ─────────────────────────────────────────
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "staging", "test",
    "admin", "blog", "shop", "store", "app", "mobile", "m",
    "cdn", "static", "assets", "media", "images", "img",
    "smtp", "pop", "imap", "vpn", "remote", "secure",
    "portal", "dashboard", "status", "docs", "help", "support",
    "forum", "community", "wiki", "gitlab", "github", "git",
    "jenkins", "jira", "confluence", "monitor", "analytics",
    "beta", "alpha", "old", "new", "v2", "v1", "api2",
    "backend", "frontend", "web", "ns1", "ns2", "mx",
]

@app.route("/api/subdomain-scan", methods=["POST"])
def subdomain_scan():
    """Try to resolve common subdomains via DNS"""
    data = request.get_json()
    if not data or "domain" not in data:
        return error("Missing 'domain' field")

    domain = data["domain"].strip().lower()
    found = []

    def check_subdomain(sub):
        """Try DNS resolution for one subdomain"""
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return {"subdomain": full, "ip": ip, "status": "resolved"}
        except socket.gaierror:
            return None  # Not found, skip it

    # Check all subdomains in parallel (much faster than sequential)
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(check_subdomain, COMMON_SUBDOMAINS)

    found = [r for r in results if r is not None]

    return success({
        "domain": domain,
        "total_found": len(found),
        "subdomains": found
    })


# ─────────────────────────────────────────
# 2. DIRECTORY FUZZER
#    POST /api/dir-fuzz
#    Input:  { "url": "https://example.com", "paths": ["/admin", "/login"] }
#    Output: Each path with HTTP status code & response time
# ─────────────────────────────────────────
@app.route("/api/dir-fuzz", methods=["POST"])
def dir_fuzz():
    """Check which paths exist on a web server"""
    data = request.get_json()
    if not data or "url" not in data or "paths" not in data:
        return error("Missing 'url' or 'paths' fields")

    base_url = data["url"].rstrip("/")
    paths = data["paths"]

    if not isinstance(paths, list) or len(paths) == 0:
        return error("'paths' must be a non-empty list")

    if len(paths) > 200:
        return error("Max 200 paths allowed per request")

    results = []

    def check_path(path):
        """Send a GET request and record the status code"""
        if not path.startswith("/"):
            path = "/" + path
        full_url = base_url + path
        try:
            resp = requests.get(
                full_url,
                timeout=5,
                allow_redirects=False,  # Don't follow redirects (shows real status)
                headers={"User-Agent": "CyberRecon/1.0"}
            )
            status = resp.status_code
            # Classify the result
            if status == 200:
                label = "FOUND"
            elif status in (301, 302, 307, 308):
                label = "REDIRECT"
            elif status == 403:
                label = "FORBIDDEN"
            elif status == 401:
                label = "UNAUTHORIZED"
            elif status == 404:
                label = "NOT FOUND"
            elif status == 500:
                label = "SERVER ERROR"
            else:
                label = f"HTTP {status}"

            return {
                "path": path,
                "url": full_url,
                "status_code": status,
                "label": label
            }
        except requests.exceptions.Timeout:
            return {"path": path, "url": full_url, "status_code": None, "label": "TIMEOUT"}
        except requests.exceptions.ConnectionError:
            return {"path": path, "url": full_url, "status_code": None, "label": "CONNECTION ERROR"}
        except Exception as e:
            return {"path": path, "url": full_url, "status_code": None, "label": f"ERROR: {str(e)}"}

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(check_path, paths))

    return success({
        "base_url": base_url,
        "total_checked": len(results),
        "results": results
    })


# ─────────────────────────────────────────
# 3. HTTP HEADER ANALYZER
#    POST /api/headers
#    Input:  { "url": "https://example.com" }
#    Output: All headers present, plus security headers that are missing
# ─────────────────────────────────────────

# Security headers every good site should have
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cache-Control",
]

@app.route("/api/headers", methods=["POST"])
def check_headers():
    """Fetch a URL and analyze its HTTP response headers"""
    data = request.get_json()
    if not data or "url" not in data:
        return error("Missing 'url' field")

    url = data["url"].strip()
    try:
        resp = requests.get(url, timeout=10, headers={"User-Agent": "CyberRecon/1.0"})
        headers_dict = dict(resp.headers)

        # Check which security headers are present vs missing
        security_analysis = []
        for h in SECURITY_HEADERS:
            present = h in headers_dict
            security_analysis.append({
                "header": h,
                "present": present,
                "value": headers_dict.get(h, None)
            })

        missing_count = sum(1 for s in security_analysis if not s["present"])

        return success({
            "url": url,
            "status_code": resp.status_code,
            "all_headers": headers_dict,
            "security_headers": security_analysis,
            "missing_security_headers": missing_count,
            "total_headers": len(headers_dict)
        })
    except requests.exceptions.Timeout:
        return error("Request timed out")
    except requests.exceptions.ConnectionError:
        return error("Could not connect to the URL")
    except Exception as e:
        return error(str(e))


# ─────────────────────────────────────────
# 4. IP LOOKUP
#    POST /api/ip-lookup
#    Input:  { "ip": "8.8.8.8" }
#    Output: Location, ISP, timezone info
# ─────────────────────────────────────────
@app.route("/api/ip-lookup", methods=["POST"])
def ip_lookup():
    """Look up geolocation and ISP info for an IP address using ipinfo.io"""
    data = request.get_json()
    if not data or "ip" not in data:
        return error("Missing 'ip' field")

    ip = data["ip"].strip()
    try:
        # ipinfo.io free tier — no API key needed for basic use
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if resp.status_code != 200:
            return error("Could not fetch IP info")

        info = resp.json()

        # Parse coordinates if available
        coords = info.get("loc", "").split(",")
        lat = coords[0] if len(coords) == 2 else None
        lon = coords[1] if len(coords) == 2 else None

        return success({
            "ip": info.get("ip"),
            "hostname": info.get("hostname", "N/A"),
            "city": info.get("city", "N/A"),
            "region": info.get("region", "N/A"),
            "country": info.get("country", "N/A"),
            "org": info.get("org", "N/A"),       # ISP / Organization
            "timezone": info.get("timezone", "N/A"),
            "latitude": lat,
            "longitude": lon,
            "postal": info.get("postal", "N/A")
        })
    except Exception as e:
        return error(str(e))


# ─────────────────────────────────────────
# 5. WHOIS LOOKUP
#    POST /api/whois
#    Input:  { "domain": "example.com" }
#    Output: Registrar, creation/expiry dates, nameservers
# ─────────────────────────────────────────
@app.route("/api/whois", methods=["POST"])
def whois_lookup():
    """Fetch WHOIS registration data for a domain"""
    data = request.get_json()
    if not data or "domain" not in data:
        return error("Missing 'domain' field")

    domain = data["domain"].strip()
    try:
        w = whois.whois(domain)

        # Helper: convert datetime objects to strings
        def fmt_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d.strftime("%Y-%m-%d %H:%M:%S")
            return str(d) if d else "N/A"

        return success({
            "domain": domain,
            "registrar": w.registrar or "N/A",
            "creation_date": fmt_date(w.creation_date),
            "expiration_date": fmt_date(w.expiration_date),
            "updated_date": fmt_date(w.updated_date),
            "name_servers": w.name_servers or [],
            "status": w.status or "N/A",
            "emails": w.emails or [],
            "country": w.country or "N/A",
            "org": w.org or "N/A"
        })
    except Exception as e:
        return error(f"WHOIS lookup failed: {str(e)}")


# ─────────────────────────────────────────
# 6. SSL CERTIFICATE CHECK
#    POST /api/ssl-check
#    Input:  { "domain": "example.com" }
#    Output: SSL valid, expiry, issuer info
# ─────────────────────────────────────────
@app.route("/api/ssl-check", methods=["POST"])
def ssl_check():
    """Inspect the SSL/TLS certificate of a domain"""
    data = request.get_json()
    if not data or "domain" not in data:
        return error("Missing 'domain' field")

    domain = data["domain"].strip().replace("https://", "").replace("http://", "").split("/")[0]

    try:
        # Connect and grab the certificate
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

        # Parse expiry date
        expiry_str = cert.get("notAfter", "")
        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z") if expiry_str else None
        days_left = (expiry_dt - datetime.utcnow()).days if expiry_dt else None

        # Parse issuer info
        issuer_dict = {}
        for item in cert.get("issuer", []):
            for k, v in item:
                issuer_dict[k] = v

        # Parse subject (who the cert is issued to)
        subject_dict = {}
        for item in cert.get("subject", []):
            for k, v in item:
                subject_dict[k] = v

        return success({
            "domain": domain,
            "ssl_valid": True,
            "issued_to": subject_dict.get("commonName", "N/A"),
            "issued_by": issuer_dict.get("organizationName", "N/A"),
            "issuer_country": issuer_dict.get("countryName", "N/A"),
            "valid_from": cert.get("notBefore", "N/A"),
            "valid_until": expiry_str or "N/A",
            "days_remaining": days_left,
            "is_expired": days_left < 0 if days_left is not None else None,
            "cipher_suite": cipher[0] if cipher else "N/A",
            "ssl_version": cipher[1] if cipher else "N/A",
            "san": [x[1] for x in cert.get("subjectAltName", [])]
        })
    except ssl.SSLError as e:
        return success({
            "domain": domain,
            "ssl_valid": False,
            "error": str(e)
        })
    except socket.timeout:
        return error("Connection timed out")
    except ConnectionRefusedError:
        return success({"domain": domain, "ssl_valid": False, "error": "Port 443 is closed (no HTTPS)"})
    except Exception as e:
        return error(str(e))


# ─────────────────────────────────────────
# 7. PORT SCANNER
#    POST /api/port-scan
#    Input:  { "host": "example.com", "ports": [80,443,22] }
#    Output: Each port marked open or closed
# ─────────────────────────────────────────
@app.route("/api/port-scan", methods=["POST"])
def port_scan():
    """Check whether specific TCP ports are open on a host"""
    data = request.get_json()
    if not data or "host" not in data or "ports" not in data:
        return error("Missing 'host' or 'ports' fields")

    host = data["host"].strip()
    ports = data["ports"]

    if not isinstance(ports, list) or len(ports) == 0:
        return error("'ports' must be a non-empty list")

    if len(ports) > 100:
        return error("Max 100 ports allowed per scan")

    # Common port name mappings
    PORT_NAMES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB", 9200: "Elasticsearch"
    }

    results = []

    def check_port(port):
        """Try to open a TCP connection to the port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)  # Short timeout for faster scanning
            result = sock.connect_ex((host, port))
            sock.close()
            is_open = result == 0
            return {
                "port": port,
                "service": PORT_NAMES.get(port, "Unknown"),
                "status": "OPEN" if is_open else "CLOSED",
                "open": is_open
            }
        except Exception as e:
            return {"port": port, "service": PORT_NAMES.get(port, "Unknown"), "status": "ERROR", "open": False}

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(check_port, ports))

    open_count = sum(1 for r in results if r["open"])

    return success({
        "host": host,
        "total_scanned": len(results),
        "open_ports": open_count,
        "results": results
    })


# ─────────────────────────────────────────
# 8. DNS LOOKUP
#    POST /api/dns-lookup
#    Input:  { "domain": "example.com" }
#    Output: A, MX, CNAME, TXT, NS records
# ─────────────────────────────────────────
@app.route("/api/dns-lookup", methods=["POST"])
def dns_lookup():
    """Fetch all common DNS record types for a domain"""
    data = request.get_json()
    if not data or "domain" not in data:
        return error("Missing 'domain' field")

    domain = data["domain"].strip()
    records = {}

    # List of record types we want to check
    record_types = ["A", "AAAA", "MX", "CNAME", "TXT", "NS", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []  # Record type doesn't exist
        except dns.resolver.NXDOMAIN:
            return error(f"Domain '{domain}' does not exist")
        except dns.exception.Timeout:
            records[rtype] = ["TIMEOUT"]
        except Exception:
            records[rtype] = []  # Skip errors silently for individual types

    # Count total records found
    total = sum(len(v) for v in records.values() if v != ["TIMEOUT"])

    return success({
        "domain": domain,
        "total_records": total,
        "records": records
    })


# ─────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    """Simple endpoint to verify the server is running"""
    return success({"message": "CyberRecon API is running!", "version": "1.0"})


# ─────────────────────────────────────────
# RUN THE APP
# ─────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print(" CyberRecon Web Suite - Backend Server")
    print(" Running at: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)
