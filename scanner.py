#!/usr/bin/env python3
"""
VulnScanner — Web Vulnerability Scanner
Uso exclusivo en sistemas con autorización explícita.
"""
import argparse
import sys
import warnings

warnings.filterwarnings("ignore")  # Suppress SSL warnings

from utils.http import create_session, normalize_url
from utils.reporter import Reporter, BOLD, CYAN, RESET, GREEN
from modules import headers, xss, sqli, redirect, dirlisting

BANNER = f"""
{BOLD}{CYAN}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝
  ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
{RESET}
{BOLD}  Web Vulnerability Scanner — Solo usar en sistemas autorizados{RESET}
  Autor: Carlos Santiago Patiño Reyes | github.com/SantiagoP0815
"""

MODULES = {
    "headers": headers.check,
    "xss": xss.check,
    "sqli": sqli.check,
    "redirect": redirect.check,
    "dirlisting": dirlisting.check,
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="VulnScanner — Web Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True, help="URL objetivo (ej: https://example.com)")
    parser.add_argument(
        "-m",
        "--modules",
        default="all",
        help="Módulos a ejecutar separados por coma (default: all)\n"
             "Opciones: headers, xss, sqli, redirect, dirlisting",
    )
    parser.add_argument("-o", "--output", help="Guardar reporte en archivo JSON (ej: reporte.json)")
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    url = normalize_url(args.url)
    print(f"{BOLD}  Target : {GREEN}{url}{RESET}")

    selected = list(MODULES.keys()) if args.modules == "all" else [m.strip() for m in args.modules.split(",")]
    invalid = [m for m in selected if m not in MODULES]
    if invalid:
        print(f"\n  [!] Módulos no reconocidos: {', '.join(invalid)}")
        print(f"  Disponibles: {', '.join(MODULES.keys())}")
        sys.exit(1)

    session = create_session()
    reporter = Reporter(url)

    for name in selected:
        MODULES[name](session, url, reporter)

    reporter.summary()

    if args.output:
        reporter.save_json(args.output)


if __name__ == "__main__":
    main()
