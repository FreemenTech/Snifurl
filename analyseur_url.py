from urllib.parse import urlparse, unquote
import ipaddress
import re
import tldextract
import ssl
import whois
import dns.resolver
from datetime import datetime, timezone
import socket
from concurrent.futures import ThreadPoolExecutor


SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq',
    'top', 'xyz', 'club', 'work', 'date', 'download', 'loan',
    'pw', 'bid', 'win', 'men', 'accountant', 'faith', 'cricket',
    'science', 'stream', 'racing', 'webcam', 'review', 'trade',
    'mom', 'lol', 'party',
    'click', 'site', 'online', 'tech', 'store', 'fun', 'life',
    'live', 'media', 'digital', 'world', 'icu', 'rest', 'bar', 'ink',
    'ru', 'su', 'cn',
    'crypto', 'coin', 'wallet', 'blockchain', 'bitcoin',
    'info', 'biz',
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "short.link",
    "cutt.ly", "rebrand.ly", "is.gd", "buff.ly", "bl.ink", "tiny.cc",
    "lnkd.in", "shorte.st", "adf.ly", "shorturl.at", "rb.gy", "v.gd",
    "tiny.one", "clck.ru", "soo.gd", "short.run", "n9.cl", "chilp.it",
    "short.cm", "shrtco.de", "9qr.de", "short2url.com", "linkd.in",
    "tiny.ie", "urlzs.com", "shorturl.is", "bc.vc", "xsurl.com",
    "tny.im", "s.id", "qr.net", "u.to", "yourls.org",
}

KNOWN_BRANDS = {
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "ebay", "linkedin", "twitter", "tiktok",
    "snapchat", "bankofamerica", "chase", "wellsfargo", "citibank",
    "hsbc", "barclays", "dhl", "fedex", "ups", "usps", "laposte",
    "colissimo", "impots", "ameli", "caf", "coinbase", "binance",
    "kraken", "metamask", "dropbox", "onedrive", "icloud", "wetransfer",
    "orange", "sfr", "bouygues",
}

#====================== FUNCTIONS =======================
def decompose_url(url: str) -> dict:
    try:
        parsed = urlparse(url)
        return {
            "scheme":   parsed.scheme,
            "netloc":   parsed.netloc,
            "hostname": parsed.hostname,
            "port":     parsed.port,
            "path":     parsed.path,
            "params":   parsed.params,
            "query":    parsed.query,
            "fragment": parsed.fragment,
        }
    except Exception as e:
        return {"error": str(e)}


def url_length(url: str) -> int:
    return len(url)


def detect_at_character(url: str) -> bool:
    return "@" in url


def detect_number_in_domain(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname or ""
        return any(c.isdigit() for c in hostname)
    except Exception:
        return False


def path_depth(url: str) -> int:
    try:
        path = urlparse(url).path
        return len([p for p in path.split("/") if p])
    except Exception:
        return 0


def detect_ip_address_in_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        full = parsed.netloc + parsed.path + parsed.params + parsed.query
        for part in re.split(r'[/:?&=]', full):
            try:
                ipaddress.ip_address(part)
                return True
            except ValueError:
                continue
        return False
    except Exception:
        return False


def detect_suspicious_tld(url: str):
    try:
        extracted = tldextract.extract(url)
        tld = extracted.suffix.split(".")[-1].lower()
        return tld if tld in SUSPICIOUS_TLDS else None
    except Exception:
        return None


def detect_tirets(url: str) -> int:
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain or ""
        return domain.count("-")
    except Exception:
        return 0


def detect_url_encoding_excessive(url: str) -> int:
    try:
        return url.count("%")
    except Exception:
        return 0


def nbr_subdomain_tldextract(url: str) -> int:
    try:
        extracted = tldextract.extract(url)
        if extracted.subdomain:
            parts = [p for p in extracted.subdomain.split(".") if p != "www"]
            return len(parts)
        return 0
    except Exception:
        return 0


def detect_https(url: str) -> bool:
    return urlparse(url).scheme.lower() == "https"


def detect_url_shortener(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname or ""
        if not hostname:
            return False
        hostname = hostname.lower().removeprefix("www.")
        return hostname in SHORTENERS
    except Exception:
        return False


def detect_standard_port(url: str):
    try:
        port = urlparse(url).port
        if port and port not in (80, 443):
            return port
        return None
    except Exception:
        return None


def detect_double_extension(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        patterns = [
            r'\.\w{2,5}\.\w{2,5}$',
            r'\.\w{2,5}\.\w{2,5}[?#]',
            r'\.(php|exe|bat|sh|asp|cgi)\.(jpg|png|gif|pdf|doc|txt)',
            r'\.tar\.(gz|bz2|xz)',
        ]
        for pattern in patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        if '%2e' in url.lower():
            decoded = unquote(url)
            if decoded != url:
                return detect_double_extension(decoded)
        return False
    except Exception:
        return False


def detect_brand_in_subdomain(url: str) -> list:
    try:
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain.lower()
        path = urlparse(url).path.lower()
        found = []
        for brand in KNOWN_BRANDS:
            pattern = rf'\b{re.escape(brand)}\b'
            if re.search(pattern, subdomain) or re.search(pattern, path):
                found.append(brand)
        return found
    except Exception:
        return []


def detect_homograph(url: str) -> list:
    try:
        hostname = urlparse(url).hostname or ""
        return [char for char in hostname if ord(char) > 127]
    except Exception:
        return []

#========================= DNS/WHOIS/SSL ==================
def verify_dns_existence(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname or ""
        if not hostname:
            return False
        dns.resolver.resolve(hostname, 'A', lifetime=3.0)
        return True
    except Exception:
        return False


def get_whois_info(url: str) -> dict:
    try:
        hostname = urlparse(url).hostname or ""
        parts = hostname.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        w = whois.whois(domain)

        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        age_days = None
        if creation_date:
            now = datetime.now(timezone.utc) if creation_date.tzinfo else datetime.now()
            age_days = (now - creation_date).days

        return {
            "domain":          domain,
            "registrar":       w.registrar,
            "creation_date":   str(creation_date),
            "expiration_date": str(expiration_date),
            "age_days":        age_days,
            "country":         w.country,
            "name_servers":    w.name_servers,
        }
    except Exception as e:
        return {"error": str(e)}


def check_ssl_certificate(url: str) -> dict:
    try:
        hostname = urlparse(url).hostname or ""
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))

        return {
            "valid":       True,
            "subject_cn":  subject.get("commonName"),
            "issuer_org":  issuer.get("organizationName"),
            "expires":     cert.get("notAfter", ""),
            "self_signed": subject == issuer,
        }
    except ssl.SSLCertVerificationError:
        return {"valid": False, "error": "Invalid or self-signed certificate"}
    except Exception as e:
        return {"valid": None, "error": str(e)}


def _fetch_whois_with_timeout(domain: str, timeout: int = 6) -> dict:
    import threading
    result = {}
    exc = []

    def run():
        try:
            hostname_parts = domain.split(".")
            d = ".".join(hostname_parts[-2:]) if len(hostname_parts) >= 2 else domain
            w = whois.whois(d)

            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            age_days = None
            if creation_date:
                now = datetime.now(timezone.utc) if creation_date.tzinfo else datetime.now()
                age_days = (now - creation_date).days

            result.update({
                "domain":          d,
                "registrar":       w.registrar,
                "creation_date":   str(creation_date),
                "expiration_date": str(expiration_date),
                "age_days":        age_days,
                "country":         w.country,
                "name_servers":    w.name_servers,
            })
        except Exception as e:
            exc.append(e)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout)

    if exc:
        return {"error": str(exc[0])}
    if not result:
        return {"error": "WHOIS timeout"}
    return result

#======================= COMPLETE ANALYZE ==================
def analyze_url(url: str) -> dict:
    results = {
        "url":                    url,
        "decomposition":          decompose_url(url),
        "length":                 url_length(url),
        "uses_https":             detect_https(url),
        "has_ip":                 detect_ip_address_in_url(url),
        "has_at_char":            detect_at_character(url),
        "suspicious_tld":         detect_suspicious_tld(url),
        "nb_subdomains":          nbr_subdomain_tldextract(url),
        "path_depth":             path_depth(url),
        "tirets_in_domain":       detect_tirets(url),
        "numbers_in_domain":      detect_number_in_domain(url),
        "non_standard_port":      detect_standard_port(url),
        "double_extension":       detect_double_extension(url),
        "excessive_url_encoding": detect_url_encoding_excessive(url),
        "brand_in_subdomain":     detect_brand_in_subdomain(url),
        "homograph_chars":        detect_homograph(url),
        "is_url_shortener":       detect_url_shortener(url),
    }

    hostname = (results["decomposition"] or {}).get("hostname", "") or ""

    def fetch_dns():
        return verify_dns_existence(url)

    def fetch_whois():
        return _fetch_whois_with_timeout(hostname, timeout=6)

    def fetch_ssl():
        return check_ssl_certificate(url)

    with ThreadPoolExecutor(max_workers=3) as executor:
        f_dns   = executor.submit(fetch_dns)
        f_whois = executor.submit(fetch_whois)
        f_ssl   = executor.submit(fetch_ssl)

        dns_result   = f_dns.result()
        whois_result = f_whois.result()
        ssl_result   = f_ssl.result()

    age = whois_result.get("age_days")
    recently = (age < 30) if age is not None else None

    results["dns_exists"]       = dns_result
    results["whois"]            = whois_result
    results["recently_created"] = recently
    results["ssl_certificate"]  = ssl_result

    return results
