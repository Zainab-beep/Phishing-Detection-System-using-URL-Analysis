import re
from urllib.parse import urlparse
import datetime

def get_domain_age(domain):
    """
    Returns domain age in days, or -1 if it cannot be determined.
    Strips 'www.' prefix before querying WHOIS.
    """
    try:
        import whois  # imported here so app still loads if package missing
        # Remove port if present (e.g. localhost:5000)
        domain = domain.split(":")[0]
        # Strip leading 'www.'
        if domain.startswith("www."):
            domain = domain[4:]

        w = whois.whois(domain)
        creation_date = w.creation_date

        if creation_date is None:
            return -1

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Normalize to naive datetime (strip timezone) to avoid comparison errors
        if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)

        age = (datetime.datetime.now() - creation_date).days
        return age
    except Exception:
        return -1


def check_url(url):
    """
    Runs heuristic checks on a URL and returns:
      - score   (int)       : cumulative risk score
      - verdict (str)       : 'Phishing' | 'Suspicious' | 'Legitimate'
      - results (dict)      : per-check label → status string
    """
    score = 0
    results = {}

    # ------------------------------------------------------------------ #
    # Guard: ensure url has a scheme so urlparse works correctly
    # ------------------------------------------------------------------ #
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc  # includes port if present

    # ------------------------------------------------------------------ #
    # 1. URL Length
    # ------------------------------------------------------------------ #
    if len(url) > 75:
        score += 2
        results["URL Length"] = "⚠️ Suspicious (> 75 chars)"
    else:
        results["URL Length"] = "✅ Safe"

    # ------------------------------------------------------------------ #
    # 2. IP Address used instead of domain name
    # ------------------------------------------------------------------ #
    if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", url):
        score += 3
        results["IP Address"] = "🚨 Detected"
    else:
        results["IP Address"] = "✅ Not Found"

    # ------------------------------------------------------------------ #
    # 3. @ Symbol (browser ignores everything before @)
    # ------------------------------------------------------------------ #
    if "@" in url:
        score += 3
        results["@ Symbol"] = "🚨 Present"
    else:
        results["@ Symbol"] = "✅ Not Present"

    # ------------------------------------------------------------------ #
    # 4. HTTPS
    # ------------------------------------------------------------------ #
    if not parsed.scheme == "https":
        score += 2
        results["HTTPS"] = "⚠️ No"
    else:
        results["HTTPS"] = "✅ Yes"

    # ------------------------------------------------------------------ #
    # 5. Hyphen in domain name
    # ------------------------------------------------------------------ #
    # Only check the hostname, not the path
    hostname = domain.split(":")[0]
    if "-" in hostname:
        score += 1
        results["Hyphen in Domain"] = "⚠️ Present"
    else:
        results["Hyphen in Domain"] = "✅ Not Present"

    # ------------------------------------------------------------------ #
    # 6. Excessive subdomains
    # ------------------------------------------------------------------ #
    if hostname.count(".") >= 3:
        score += 2
        results["Subdomains"] = "⚠️ Too Many"
    else:
        results["Subdomains"] = "✅ Normal"

    # ------------------------------------------------------------------ #
    # 7. Phishing keywords in URL
    # ------------------------------------------------------------------ #
    keywords = ["login", "verify", "update", "secure", "bank",
                "account", "confirm", "password", "signin", "ebayisapi"]
    found = [kw for kw in keywords if kw in url.lower()]
    if found:
        score += 2
        results["Keywords"] = f"⚠️ Found: {', '.join(found)}"
    else:
        results["Keywords"] = "✅ Clean"

    # ------------------------------------------------------------------ #
    # 8. URL shortener
    # ------------------------------------------------------------------ #
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co",
                  "ow.ly", "is.gd", "buff.ly", "short.link"]
    if any(s in hostname for s in shorteners):
        score += 3
        results["URL Shortener"] = "🚨 Detected"
    else:
        results["URL Shortener"] = "✅ Not Used"

    # ------------------------------------------------------------------ #
    # 9. Domain age via WHOIS
    # ------------------------------------------------------------------ #
    age = get_domain_age(hostname)
    if age == -1:
        results["Domain Age"] = "ℹ️ Unknown (WHOIS unavailable)"
    elif age < 180:
        score += 2
        results["Domain Age"] = f"⚠️ New Domain ({age} days old)"
    else:
        results["Domain Age"] = f"✅ Established ({age} days old)"

    # ------------------------------------------------------------------ #
    # Final verdict
    # ------------------------------------------------------------------ #
    if score >= 8:
        verdict = "Phishing"
    elif score >= 4:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    return score, verdict, results
