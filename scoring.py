from analyseur_url import analyze_url


LEGITIMATE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "gitlab.com", "cloudflare.com", "akamai.com",
    "x.com", "twitter.com", "facebook.com", "instagram.com",
    "linkedin.com", "youtube.com", "netflix.com", "spotify.com",
    "paypal.com", "stripe.com", "shopify.com", "wordpress.com",
    "wikipedia.org", "mozilla.org", "python.org",
}

TRUSTED_SSL_ISSUERS = {
    "DigiCert", "Let's Encrypt", "Sectigo", "GlobalSign",
    "GoDaddy", "Entrust", "Comodo", "Amazon",
}

VERY_DANGEROUS_TLDS = {'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'pw', 'cc'}
SUSPICIOUS_TLDS_MED = {'info', 'biz', 'click', 'link', 'online', 'site', 'work', 'loan'}


def get_root_domain(hostname: str) -> str:
    parts = (hostname or "").rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def validate_analysis_results(results: dict) -> dict:
    expected_keys = [
        "has_ip", "has_at_char", "suspicious_tld", "nb_subdomains",
        "path_depth", "tirets_in_domain", "numbers_in_domain",
        "non_standard_port", "double_extension", "excessive_url_encoding",
        "brand_in_subdomain", "homograph_chars", "is_url_shortener",
        "dns_exists", "whois", "recently_created", "ssl_certificate",
        "uses_https", "length", "decomposition",
    ]
    for key in expected_keys:
        if key not in results:
            results[key] = None
    return results


def calculate_phishing_score(url: str) -> dict:
    results = validate_analysis_results(analyze_url(url))

    score_absolute = 0
    score_standard = 0
    penalties      = 0
    details        = []

    hostname    = (results.get("decomposition") or {}).get("hostname", "") or ""
    root_domain = get_root_domain(hostname)
    ssl_info    = results.get("ssl_certificate") or {}
    whois_info  = results.get("whois") or {}

    is_known_legitimate = root_domain in LEGITIMATE_DOMAINS
    is_shortener        = bool(results.get("is_url_shortener"))
    dns_ok              = results.get("dns_exists") is True
    real_dns_fail       = (results.get("dns_exists") is False) and not is_shortener
    ssl_valid           = ssl_info.get("valid")
    age_days            = whois_info.get("age_days")

    has_homograph = bool(results.get("homograph_chars"))
    has_ip        = bool(results.get("has_ip"))
    has_at        = bool(results.get("has_at_char"))
    has_dbl_ext   = bool(results.get("double_extension"))

    if has_homograph:
        score_absolute += 35
        details.append(f"Homograph characters {results['homograph_chars']} (+35) [ABSOLUTE]")

    if has_ip:
        score_absolute += 30
        details.append("Direct IP in URL (+30) [ABSOLUTE]")

    if has_at:
        score_absolute += 20
        details.append("@ character in URL (+20) [ABSOLUTE]")

    if has_dbl_ext:
        score_absolute += 15
        details.append("Double extension (+15) [ABSOLUTE]")

    if is_shortener:
        score_absolute += 25
        details.append("Shortened URL — hidden destination (+25) [ABSOLUTE]")

    if dns_ok or is_known_legitimate:
        if ssl_valid is False:
            score_standard += 20
            details.append("Invalid or missing SSL certificate (+20)")
        elif ssl_valid is None and results.get("uses_https"):
            score_standard += 10
            details.append("SSL verification failed (+10)")

    if results.get("recently_created") is True:
        score_standard += 20
        details.append("Domain created less than 30 days ago (+20)")

    suspicious_tld = results.get("suspicious_tld")
    if suspicious_tld:
        if suspicious_tld in VERY_DANGEROUS_TLDS:
            score_standard += 15
            details.append(f"Extremely dangerous TLD (.{suspicious_tld}) (+15)")
        elif suspicious_tld in SUSPICIOUS_TLDS_MED:
            score_standard += 8
            details.append(f"Suspicious TLD (.{suspicious_tld}) (+8)")
        else:
            score_standard += 4
            details.append(f"Unusual TLD (.{suspicious_tld}) (+4)")

    brands = results.get("brand_in_subdomain") or []
    if brands and not is_known_legitimate:
        score_standard += 15
        details.append(f"Brand '{brands[0]}' impersonated in subdomain/path (+15)")

    if real_dns_fail:
        score_standard += 8
        details.append("Domain has no DNS record (+8)")

    port = results.get("non_standard_port")
    if port:
        score_standard += 6
        details.append(f"Non-standard port ({port}) (+6)")

    encoding_count = results.get("excessive_url_encoding") or 0
    if encoding_count > 10:
        score_standard += 8
        details.append(f"Massive URL encoding ({encoding_count} occurrences) (+8)")
    elif encoding_count > 3:
        score_standard += 4
        details.append(f"Moderate URL encoding ({encoding_count} occurrences) (+4)")

    nb_subdomains = results.get("nb_subdomains") or 0
    if nb_subdomains >= 4:
        score_standard += 6
        details.append(f"Abnormal number of subdomains ({nb_subdomains}) (+6)")
    elif nb_subdomains >= 2:
        score_standard += 3
        details.append(f"Multiple subdomains ({nb_subdomains}) (+3)")

    tirets = results.get("tirets_in_domain") or 0
    if tirets >= 3:
        score_standard += 5
        details.append(f"Many hyphens in domain ({tirets}) (+5)")
    elif tirets >= 2:
        score_standard += 3
        details.append(f"Hyphens in domain ({tirets}) (+3)")
    elif tirets == 1 and not is_known_legitimate:
        score_standard += 1
        details.append("Hyphen in domain (+1)")

    if results.get("numbers_in_domain"):
        digit_count = sum(c.isdigit() for c in hostname)
        if digit_count >= 4:
            score_standard += 5
            details.append(f"Many digits in domain ({digit_count}) (+5)")
        elif digit_count >= 2:
            score_standard += 2
            details.append(f"Digits in domain ({digit_count}) (+2)")

    url_len = results.get("length") or 0
    if url_len > 120:
        score_standard += 4
        details.append(f"Very long URL ({url_len} characters) (+4)")
    elif url_len > 80:
        score_standard += 2
        details.append(f"Long URL ({url_len} characters) (+2)")

    depth = results.get("path_depth") or 0
    if depth >= 5:
        score_standard += 3
        details.append(f"Very deep path ({depth} levels) (+3)")
    elif depth >= 3:
        score_standard += 1
        details.append(f"Deep path ({depth} levels) (+1)")

    if not results.get("uses_https") and dns_ok:
        score_standard += 5
        details.append("No HTTPS on active domain (+5)")

    can_penalize = not is_shortener and not real_dns_fail

    if can_penalize:

        if ssl_valid is True:
            org = str(ssl_info.get("issuer_org", ""))
            if any(t in org for t in TRUSTED_SSL_ISSUERS):
                penalties += 8
                details.append("Valid SSL from trusted issuer (-8)")

        suspicion_count = sum([
            bool(suspicious_tld),
            bool(brands and not is_known_legitimate),
            tirets >= 2,
            nb_subdomains >= 2,
        ])

        if age_days:
            if suspicion_count >= 2:
                if age_days > 730:
                    penalties += 5
                    details.append("Domain older than 2 years (suspicious context, -5)")
                elif age_days > 365:
                    penalties += 3
                    details.append("Domain older than 1 year (suspicious context, -3)")
            else:
                if age_days > 730:
                    penalties += 10
                    details.append("Domain older than 2 years (-10)")
                elif age_days > 365:
                    penalties += 7
                    details.append("Domain older than 1 year (-7)")
                elif age_days > 180:
                    penalties += 4
                    details.append("Domain older than 6 months (-4)")

        if is_known_legitimate:
            penalties += 12
            details.append(f"Known legitimate root domain ({root_domain}) (-12)")

    score_standard_net = max(0, score_standard - penalties)
    raw_score = score_absolute + score_standard_net

    if has_homograph:
        raw_score = max(raw_score, 75)
        details.append("→ Homograph floor score applied (min 75)")

    if has_ip and not results.get("uses_https"):
        raw_score = max(raw_score, 65)
        details.append("→ IP+HTTP floor score applied (min 65)")

    if is_shortener:
        raw_score = max(raw_score, 50)
        details.append("→ Shortener floor score applied (min 50)")

    score = min(100, max(0, raw_score))

    if score >= 75:
        risk_level     = "CRITICAL"
        recommendation = "🚨 BLOCK IMMEDIATELY — Phishing almost certain"
    elif score >= 55:
        risk_level     = "HIGH"
        recommendation = "⚠️ VERY SUSPICIOUS — Block unless explicitly trusted"
    elif score >= 35:
        risk_level     = "MEDIUM"
        recommendation = "🔍 SUSPICIOUS — Manual inspection recommended"
    elif score >= 15:
        risk_level     = "LOW"
        recommendation = "ℹ️ LOW RISK — Probably safe, stay cautious"
    else:
        risk_level     = "SAFE"
        recommendation = "✅ LEGITIMATE — No significant indicators"

    return {
        "url":            url,
        "score":          score,
        "risk_level":     risk_level,
        "recommendation": recommendation,
        "details":        details,
        "raw_results":    results,
        "_debug": {
            "score_absolute":     score_absolute,
            "score_standard":     score_standard,
            "penalties":          penalties,
            "score_standard_net": score_standard_net,
            "raw_score":          raw_score,
            "is_shortener":       is_shortener,
            "is_known_legit":     is_known_legitimate,
            "dns_ok":             dns_ok,
            "real_dns_fail":      real_dns_fail,
            "can_penalize":       can_penalize,
        }
    }
