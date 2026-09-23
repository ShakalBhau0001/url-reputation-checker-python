import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse


class URLReputationChecker:
    # Suspicious keyword patterns commonly found in phishing URLs
    SUSPICIOUS_PATTERNS = [  # noqa: RUF012
        r"secure.*login",
        r"free.*gift",
        r"win.*prize",
        r"verify.*account",
        r"update.*payment",
        r"confirm.*identity",
        r"suspended.*account",
    ]
    RISKY_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".date"]  # noqa: RUF012
    SHORTENERS = [  # noqa: RUF012
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
    ]
    BRANDS = {  # noqa: RUF012
        "paypal": "paypal.com",
        "google": "google.com",
        "amazon": "amazon.com",
        "facebook": "facebook.com",
        "apple": "apple.com",
        "microsoft": "microsoft.com",
        "netflix": "netflix.com",
        "bank": None,
    }

    def __init__(self):
        pass

    def check_url(self, raw_url: str) -> dict:
        # Checking URL and returning a risk assessment score.
        had_scheme = raw_url.strip().lower().startswith(("http://", "https://"))
        url = raw_url.strip()
        if not had_scheme:
            url = "http://" + url

        result = {
            "url": url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # noqa: DTZ005
            "risk_score": 0,
            "risk_level": "SAFE",
            "warnings": [],
            "details": {},
        }

        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            full_url = url.lower()
            score = 0
            warnings = []

            # 1. Risky TLDs
            for tld in self.RISKY_TLDS:
                if host.endswith(tld):
                    warnings.append(f"⚠️ Risky TLD detected: {tld}")
                    score += 30
                    break  # only count once

            # 2. URL shorteners
            for shortener in self.SHORTENERS:
                if host == shortener or host.endswith("." + shortener):
                    warnings.append(f"⚠️  Shortened URL service detected: {shortener}")
                    score += 20
                    break

            # 3. IP address instead of domain name
            try:
                ipaddress.ip_address(host)
                warnings.append("⚠️  IP address used instead of a domain name")
                score += 25
            except ValueError:
                pass

            # 4. Brand impersonation
            for brand, official in self.BRANDS.items():
                if (official and brand in host and not (host == official or host.endswith("." + official))):
                    warnings.append(f"⚠️  Possible '{brand}' impersonation: {host}")
                    score += 30
                    break

            # 5. Suspicious keyword patterns anywhere in the URL
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, full_url, re.IGNORECASE):
                    warnings.append(f"⚠️  Suspicious pattern detected: '{pattern}'")
                    score += 15

            # 6. Excessive subdomains
            labels = host.split(".") if host else []
            if len(labels) > 4:
                warnings.append(f"⚠️  Excessive subdomains ({len(labels)} levels): {host}")
                score += 15

            # 7. Special / illegal characters in the authority part
            if "@" in parsed.netloc or re.search(r"[!~`\s]", host):
                warnings.append("⚠️  Suspicious characters in domain/authority")
                score += 25

            # 8. Unusually long URL
            if len(url) > 100:
                warnings.append(f"⚠️  Unusually long URL ({len(url)} chars)")
                score += 10

            # 9. Not using HTTPS
            if not url.startswith("https://"):
                warnings.append("⚠️  Not using HTTPS")
                score += 10

            score = min(score, 100)
            if score >= 60:
                risk_level = "🔴 HIGH RISK"
            elif score >= 30:
                risk_level = "🟡 MEDIUM RISK"
            elif score >= 10:
                risk_level = "🟢 LOW RISK"
            else:
                risk_level = "✅ SAFE"

            result.update(
                {
                    "risk_score": score,
                    "risk_level": risk_level,
                    "warnings": warnings,
                    "details": {
                        "domain": host,
                        "path": parsed.path.lower(),
                        "length": len(url),
                        "uses_https": url.startswith("https://"),
                        "scheme_provided_by_user": had_scheme,
                    },
                }
            )

        except Exception as e:  # noqa: BLE001
            result["warnings"].append(f"❌ Error parsing URL: {e}")
            result["risk_level"] = "❓ UNKNOWN"

        return result

    def check_multiple(self, urls: list[str]) -> list[dict]:
        return [self.check_url(u.strip()) for u in urls if u.strip()]


def print_result(result: dict) -> None:
    print(f"\n{'=' * 50}")
    print(f"  {result['risk_level']}")
    print(f"{'=' * 50}")
    print(f"  URL: {result['url']}")
    print(f"  Time: {result['timestamp']}")
    print(f"  Risk Score: {result['risk_score']}/100")

    if result["warnings"]:
        print("\n  Warnings:")
        for warning in result["warnings"]:
            print(f"    {warning}")
    else:
        print("\n  ✅ No warnings detected")

    print(f"{'=' * 50}\n")


def main():
    print("=" * 60)
    print("  🔍 URL REPUTATION CHECKER - SOC Tool")
    print("=" * 60)
    print("\nChecks URLs for phishing, malware, and suspicious patterns")
    print("(Note : Heuristic analysis only — not a live threat-intel lookup)\n")
    checker = URLReputationChecker()
    while True:
        print("-" * 60)
        print("Options:")
        print("1. Check a single URL")
        print("2. Check multiple URLs (comma-separated)")
        print("3. Demo (test with sample URLs)")
        print("0. Exit")
        choice = input("\nChoice (0-3): ").strip()
        if choice == "1":
            url = input("Enter URL: ").strip()
            if url:
                print_result(checker.check_url(url))

        elif choice == "2":
            urls = input("Enter URLs (comma-separated): ").strip()
            if urls:
                for result in checker.check_multiple(urls.split(",")):
                    print_result(result)

        elif choice == "3":
            print("\n🔬 Running demo with sample URLs...\n")
            sample_urls = [
                "https://google.com",
                "http://paypal-secure.tk/login",
                "https://bit.ly/3xK9mN2",
                "http://192.168.1.1/admin",
                "https://www.facebook.com",
                "http://free-prize-winner.xyz/claim",
                "https://github.com",
                "http://bank-verify-account.ml/update",
            ]
            for result in checker.check_multiple(sample_urls):
                print_result(result)

        elif choice == "0":
            print("\n👋 See You Soon!")
            break

        else:
            print("❌ Invalid choice! Choose Between (0-3)")


if __name__ == "__main__":
    main()
