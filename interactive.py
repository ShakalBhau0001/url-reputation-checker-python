import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

try:
    import pyfiglet as pyf
    HAS_FIGLET = True
except ImportError:
    HAS_FIGLET = False

console = Console()


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

            for tld in self.RISKY_TLDS:
                if host.endswith(tld):
                    warnings.append(f"Risky TLD detected: {tld}")
                    score += 30
                    break

            for shortener in self.SHORTENERS:
                if host == shortener or host.endswith("." + shortener):
                    warnings.append(f"Shortened URL service detected: {shortener}")
                    score += 20
                    break

            try:
                ipaddress.ip_address(host)
                warnings.append("IP address used instead of a domain name")
                score += 25
            except ValueError:
                pass

            for brand, official in self.BRANDS.items():
                if (
                    official
                    and brand in host
                    and not (host == official or host.endswith("." + official))
                ):
                    warnings.append(f"Possible '{brand}' impersonation: {host}")
                    score += 30
                    break

            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, full_url, re.IGNORECASE):
                    warnings.append(f"Suspicious pattern detected: '{pattern}'")
                    score += 15

            labels = host.split(".") if host else []
            if len(labels) > 4:
                warnings.append(f"Excessive subdomains ({len(labels)} levels): {host}")
                score += 15

            if "@" in parsed.netloc or re.search(r"[!~`\s]", host):
                warnings.append("Suspicious characters in domain/authority")
                score += 25

            if len(url) > 100:
                warnings.append(f"Unusually long URL ({len(url)} chars)")
                score += 10

            if not url.startswith("https://"):
                warnings.append("Not using HTTPS")
                score += 10

            score = min(score, 100)
            if score >= 60:
                risk_level = "HIGH RISK"
            elif score >= 30:
                risk_level = "MEDIUM RISK"
            elif score >= 10:
                risk_level = "LOW RISK"
            else:
                risk_level = "SAFE"

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
            result["warnings"].append(f"Error parsing URL: {e}")
            result["risk_level"] = "UNKNOWN"

        return result

    def check_multiple(self, urls: list[str]) -> list[dict]:
        return [self.check_url(u.strip()) for u in urls if u.strip()]


def print_banner():
    console.clear()
    banner = Text()
    if HAS_FIGLET:
        banner.append(pyf.figlet_format("URL GUARD", font="standard"), style="bold cyan")
    else:
        banner.append("URL GUARD\n", style="bold cyan")
    banner.append("Phishing & Malicious URL Detector", style="dim white")
    console.print(
        Panel(
            Align.center(banner),
            border_style="cyan",
            box=box.DOUBLE_EDGE,
        )
    )


def divider(title=""):
    console.print(Rule(title, style="cyan"))


def success(message):
    console.print(f"\n[bold green]✔[/bold green] {message}\n")


def error(message):
    console.print(f"\n[bold red]✘[/bold red] {message}\n")


def info(message):
    console.print(f"[bold yellow]ℹ[/bold yellow] {message}")


def risk_style(risk_level: str) -> str:
    if "HIGH" in risk_level:
        return "bold red"
    if "MEDIUM" in risk_level:
        return "bold yellow"
    if "LOW" in risk_level:
        return "bold green"
    if "SAFE" in risk_level:
        return "bold cyan"
    return "bold white"


def show_result(result: dict):
    style = risk_style(result["risk_level"])
    body = Text()
    body.append("URL:   ", style="dim white")
    body.append(f"{result['url']}\n", style="white")
    body.append("Time:  ", style="dim white")
    body.append(f"{result['timestamp']}\n", style="white")
    body.append("Score: ", style="dim white")
    body.append(f"{result['risk_score']}/100\n\n", style="bold white")

    if result["warnings"]:
        body.append("Warnings:\n", style="bold yellow")
        for warning in result["warnings"]:
            body.append(f"  • {warning}\n", style="white")
    else:
        body.append("No warnings detected.\n", style="bold green")

    console.print(
        Panel(
            body,
            title=result["risk_level"],
            title_align="left",
            border_style=style,
            box=box.ROUNDED,
        )
    )


def menu():
    table = Table(
        title="Main Menu",
        title_style="bold cyan",
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        padding=(0, 2),
    )
    table.add_column("Option", justify="center", style="bold yellow")
    table.add_column("Action", style="green")
    table.add_row("1", "🔍 Check a Single URL")
    table.add_row("2", "🔍 Check Multiple URLs")
    table.add_row("3", "🔬 Demo (sample URLs)")
    table.add_row("4", "ℹ About")
    table.add_row("0", "🚪 Exit")
    console.print(table)


def single_url_menu(checker: URLReputationChecker):
    divider("🔍 Check a Single URL")
    url = Prompt.ask("[bold cyan]Enter URL to check[/bold cyan]").strip()
    if not url:
        error("URL cannot be empty.")
        return
    show_result(checker.check_url(url))
    success("Check complete.")


def multiple_url_menu(checker: URLReputationChecker):
    divider("🔍 Check Multiple URLs")
    urls_input = Prompt.ask(
        "[bold cyan]Enter URLs (comma-separated)[/bold cyan]"
    ).strip()
    if not urls_input:
        error("No URLs entered.")
        return
    for result in checker.check_multiple(urls_input.split(",")): # type: ignore
        show_result(result)
    success("Check complete.")


def demo_menu(checker: URLReputationChecker):
    divider("🔬 Demo Mode")
    info("Running demo with sample URLs...\n")
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
    for result in checker.check_multiple(sample_urls): # type: ignore
        show_result(result)
    success("Demo complete.")


def about():
    divider("ℹ About Toolkit")
    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.ROUNDED,
        border_style="cyan",
    )
    table.add_column("Property", style="yellow")
    table.add_column("Value", style="green")
    table.add_row("Purpose", "Heuristic Phishing / Malicious URL Detection")
    table.add_row("Method", "Structural analysis — no live threat-intel API")
    table.add_row("Checks", "TLD, shorteners, IP host, brand spoofing, patterns, HTTPS")
    table.add_row("Risk Levels", "SAFE → LOW → MEDIUM → HIGH")
    table.add_row("Language", "Python")
    table.add_row("UI", "Rich CLI")
    console.print(table)


def main():
    checker = URLReputationChecker()
    while True:
        print_banner()
        menu()
        choice = Prompt.ask(
            "\n[bold cyan]Select Option[/bold cyan]",
            choices=["1", "2", "3", "4", "0"],
            default="1",
        )
        if choice == "1":
            single_url_menu(checker)
        elif choice == "2":
            multiple_url_menu(checker)
        elif choice == "3":
            demo_menu(checker)
        elif choice == "4":
            about()
        elif choice == "0":
            console.print()
            console.print(
                Panel(
                    Align.center(
                        Text("See You Soon! | Stay safe online. 🛡️", style="bold cyan")
                    ),
                    border_style="magenta",
                    box=box.DOUBLE_EDGE,
                )
            )
            break
        Prompt.ask("\n[dim]Press Enter to return to menu…[/dim]", default="")


if __name__ == "__main__":
    main()

