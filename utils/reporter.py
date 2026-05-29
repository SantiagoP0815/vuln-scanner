import json
from datetime import datetime

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"

SEVERITY_COLOR = {
    "HIGH": RED,
    "MEDIUM": YELLOW,
    "LOW": CYAN,
    "INFO": DIM,
}


class Reporter:
    def __init__(self, target):
        self.target = target
        self.findings = []
        self.start_time = datetime.now()

    def add(self, module, severity, title, detail, url=""):
        self.findings.append(
            {
                "module": module,
                "severity": severity,
                "title": title,
                "detail": detail,
                "url": url or self.target,
            }
        )
        color = SEVERITY_COLOR.get(severity, "")
        print(f"  {color}[{severity}]{RESET} {title}")
        if detail:
            print(f"         {DIM}{detail}{RESET}")

    def section(self, name):
        print(f"\n{BOLD}{CYAN}[*] {name}{RESET}")

    def summary(self):
        elapsed = (datetime.now() - self.start_time).seconds
        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        print(f"\n{BOLD}{'─'*50}{RESET}")
        print(f"{BOLD}  RESUMEN — {self.target}{RESET}")
        print(f"{'─'*50}")
        print(f"  {RED}HIGH   {RESET} {counts['HIGH']}")
        print(f"  {YELLOW}MEDIUM {RESET} {counts['MEDIUM']}")
        print(f"  {CYAN}LOW    {RESET} {counts['LOW']}")
        print(f"  {DIM}INFO   {RESET} {counts['INFO']}")
        print(f"  Tiempo : {elapsed}s | Hallazgos: {len(self.findings)}")
        print(f"{'─'*50}\n")

    def save_json(self, path):
        report = {
            "target": self.target,
            "date": self.start_time.isoformat(),
            "findings": self.findings,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"{GREEN}  [+] Reporte guardado en: {path}{RESET}\n")
