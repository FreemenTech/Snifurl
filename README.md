# SnifURL — URL Threat Analysis

> Real-time heuristic URL analysis to detect phishing, malware, and suspicious links.

---

## 🌐 Live Demo

SnifURL is publicly accessible — no installation required.

**👉 [https://snifurl.online](https://snifurl.online)**
![SnifURL Demo](assets/demo.gif)

Paste any URL and get an instant risk score with a full breakdown of every signal detected. Try it directly from your browser.

---

## What it does

SnifURL analyzes any URL across multiple layers and returns a risk score from **0 to 100** with a detailed breakdown of every signal detected.

**Indicators checked:**
- TLD reputation (Freenom, high-risk ccTLDs, crypto TLDs)
- Direct IP address in URL
- Brand impersonation in subdomain or path
- Homograph attacks (unicode lookalike characters)
- SSL certificate validity and issuer trust
- WHOIS domain age (recently registered = suspicious)
- DNS resolution
- URL shorteners (hidden destination)
- Double file extensions
- `@` character in URL
- Non-standard ports
- Excessive URL encoding
- Subdomain depth and hyphens

---

## Risk levels

| Score  | Level    | Meaning                                   |
|--------|----------|-------------------------------------------|
| 0–14   | SAFE     | No significant indicators                 |
| 15–34  | LOW      | Probably safe, stay cautious              |
| 35–54  | MEDIUM   | Suspicious — manual inspection            |
| 55–74  | HIGH     | Very suspicious — block unless trusted    |
| 75–100 | CRITICAL | Phishing almost certain — block           |

---

## Stack

- **Backend** — Python 3.11 / Flask
- **Analysis engine** — `analyseur_url.py` + `scoring.py`
- **Network checks** — `dnspython`, `python-whois`, `ssl` (run in parallel)
- **Frontend** — Vanilla HTML / CSS / JS
- **Deploy** — Vultr VPS / Ubuntu 22.04 / Nginx + Gunicorn

---

## Project structure

```
snifurl/
├── app.py
├── analyseur_url.py
├── scoring.py
├── requirements.txt
└── static/
    ├── index.html
    ├── style.css
    ├── app.js
    └── icons/
        ├── shield.svg
        ├── triangle-alert.svg
        └── ...
```

---

## Run locally

```bash
pip install -r requirements.txt
python app.py
```

Open [http://localhost:5000](http://localhost:5000)

---

## API

### `POST /analyze`

```json
// Request
{ "url": "https://example.com" }

// Response
{
  "url": "https://example.com",
  "score": 12,
  "risk_level": "SAFE",
  "recommendation": "LEGITIMATE — No significant indicators",
  "details": ["Known legitimate root domain (example.com) (-12)"],
  "indicators": {
    "uses_https": true,
    "dns_exists": true,
    "has_ip": false,
    "suspicious_tld": null,
    "recently_created": false,
    "ssl_certificate": { "valid": true, "issuer_org": "DigiCert" },
    "whois": { "age_days": 9862, "registrar": "..." }
  }
}
```

### `GET /health`

```json
{ "status": "ok", "service": "SnifURL API" }
```

---

## License

MIT — free to use, modify, and distribute.

**Maintainer:** Freemen HOUNGBEDJI