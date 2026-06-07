# VulnScanner

Herramienta CLI en Python para detección automatizada de vulnerabilidades web del **OWASP Top 10**. Diseñada con fines educativos y de pruebas de seguridad autorizadas.

```
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝
```

> ⚠️ **Uso exclusivo en sistemas con autorización explícita del propietario.**

---

## Módulos de detección

| Módulo | Vulnerabilidad | Severidad |
|--------|---------------|-----------|
| `headers` | Cabeceras de seguridad ausentes (HSTS, CSP, X-Frame-Options...) | HIGH / MEDIUM / LOW |
| `xss` | Cross-Site Scripting reflejado en parámetros URL y formularios | HIGH |
| `sqli` | SQL Injection error-based en parámetros URL y formularios | HIGH |
| `redirect` | Open Redirect en parámetros de redirección | MEDIUM |
| `dirlisting` | Directory Listing, rutas sensibles y archivos expuestos (`.env`, `.git`) | HIGH / MEDIUM |

---

## Instalación

```bash
git clone https://github.com/SantiagoP0815/vuln-scanner.git
cd vuln-scanner
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

---

## Uso

```bash
# Escaneo completo con reporte JSON
python3 scanner.py -u https://objetivo.com -o reporte.json

# Solo módulos específicos
python3 scanner.py -u https://objetivo.com -m headers,xss,sqli

# Ver ayuda
python3 scanner.py --help
```

### Opciones

| Argumento | Descripción |
|-----------|-------------|
| `-u`, `--url` | URL objetivo |
| `-m`, `--modules` | Módulos a ejecutar separados por coma (default: `all`) |
| `-o`, `--output` | Ruta del reporte JSON de salida |

---

## Ejemplo de salida

```
  Target : https://example.com

[*] Cabeceras de Seguridad
  [HIGH]   Falta: Strict-Transport-Security
           HSTS ausente — sin protección contra downgrade a HTTP
  [HIGH]   Falta: Content-Security-Policy
           CSP ausente — mayor riesgo de XSS
  [MEDIUM] Falta: X-Frame-Options
           X-Frame-Options ausente — vulnerable a Clickjacking
  [LOW]    Header informativo expuesto: Server
           Valor: nginx/1.18.0 — revela tecnología del servidor

[*] XSS Reflejado
  [HIGH]   XSS Reflejado en parámetro: search
           Payload reflejado: <script>alert('XSS')</script>

──────────────────────────────────────────────────
  RESUMEN — https://example.com
──────────────────────────────────────────────────
  HIGH     3
  MEDIUM   1
  LOW      2
  INFO     0
  Tiempo : 4s | Hallazgos: 6
──────────────────────────────────────────────────
```

---

## Entornos de práctica recomendados

Para probar la herramienta de forma legal y segura:

- **[DVWA](https://github.com/digininja/DVWA)** — Damn Vulnerable Web Application (Docker)
- **[HackTheBox](https://hackthebox.com)** — Máquinas retiradas
- **[TryHackMe](https://tryhackme.com)** — Rooms de Web Hacking

```bash
# Levantar DVWA con Docker
docker run -d -p 80:80 vulnerables/web-dvwa
python3 scanner.py -u http://localhost -o dvwa_report.json
```

---

## Estructura del proyecto

```
vuln-scanner/
├── scanner.py          # Punto de entrada CLI
├── requirements.txt
├── modules/
│   ├── headers.py      # Detección de cabeceras de seguridad
│   ├── xss.py          # XSS reflejado en parámetros y formularios
│   ├── sqli.py         # SQL Injection error-based
│   ├── redirect.py     # Open Redirect
│   └── dirlisting.py   # Directory Listing y rutas sensibles
└── utils/
    ├── http.py         # Cliente HTTP y extractor de formularios
    └── reporter.py     # Salida en consola (colores) y JSON
```

---

## Disclaimer

Esta herramienta es para uso **educativo y en entornos autorizados**. El autor no se hace responsable del uso indebido. Antes de escanear cualquier sistema, asegúrese de contar con permiso explícito del propietario.

---

**Autor:** Carlos Santiago Patiño Reyes  
**LinkedIn:** [carlos-santiago-patino-reyes](https://linkedin.com/in/carlos-santiago-patino-reyes)  
**Portfolio:** [santiagop0815.github.io/Portafolio](https://santiagop0815.github.io/Portafolio/)
