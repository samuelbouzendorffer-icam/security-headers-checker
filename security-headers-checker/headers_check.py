#!/usr/bin/env python3
"""headers_check : audite les en-têtes de sécurité HTTP d'une réponse (hors ligne).

Il lit des en-têtes que VOUS avez déjà récupérés (par exemple avec `curl -I https://monsite`
ou depuis les outils de développement du navigateur) : l'outil lui-même n'envoie aucune
requête réseau. À utiliser sur vos propres sites ou des sites d'entraînement.
"""
import argparse
import re
import sys
from dataclasses import dataclass

OK, WARN, FAIL = "OK", "ATTENTION", "MANQUANT"


@dataclass
class Finding:
    header: str
    status: str
    message: str


def parse_headers(text: str) -> dict:
    """Retourne {nom_minuscule: [valeurs]} (plusieurs Set-Cookie possibles)."""
    headers = {}
    for line in text.splitlines():
        if ":" not in line or line.upper().startswith("HTTP/"):
            continue
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return headers


def _first(headers: dict, name: str):
    values = headers.get(name)
    return values[0] if values else None


def check_hsts(headers):
    v = _first(headers, "strict-transport-security")
    if v is None:
        return Finding("Strict-Transport-Security", FAIL, "Absent : le navigateur n'est pas forcé à utiliser HTTPS.")
    m = re.search(r"max-age=(\d+)", v, re.I)
    age = int(m.group(1)) if m else 0
    if age < 15552000:  # ~6 mois
        return Finding("Strict-Transport-Security", WARN, f"max-age={age} : trop court (viser au moins 1 an = 31536000).")
    return Finding("Strict-Transport-Security", OK, f"max-age={age}.")


def check_csp(headers):
    v = _first(headers, "content-security-policy")
    if v is None:
        return Finding("Content-Security-Policy", FAIL, "Absent : aucune restriction sur les scripts et ressources chargés (aide contre XSS).")
    risky = [s for s in ("'unsafe-inline'", "'unsafe-eval'") if s in v]
    if re.search(r"(^|[\s;])\*([\s;]|$)", v):
        risky.append("joker *")
    if risky:
        return Finding("Content-Security-Policy", WARN, "Présent mais affaibli par : " + ", ".join(risky) + ".")
    return Finding("Content-Security-Policy", OK, "Présent, sans directive risquée évidente.")


def check_nosniff(headers):
    v = _first(headers, "x-content-type-options")
    if v is None or v.lower() != "nosniff":
        return Finding("X-Content-Type-Options", FAIL, "Absent ou différent de 'nosniff' : le navigateur peut deviner un autre type de contenu.")
    return Finding("X-Content-Type-Options", OK, "nosniff.")


def check_framing(headers):
    xfo = _first(headers, "x-frame-options")
    csp = _first(headers, "content-security-policy") or ""
    if "frame-ancestors" in csp.lower() or (xfo and xfo.upper() in ("DENY", "SAMEORIGIN")):
        return Finding("Protection anti-clickjacking", OK, "X-Frame-Options ou frame-ancestors présent.")
    return Finding("Protection anti-clickjacking", FAIL, "Ni X-Frame-Options ni frame-ancestors : la page peut être affichée dans une iframe tierce.")


def check_referrer(headers):
    if _first(headers, "referrer-policy") is None:
        return Finding("Referrer-Policy", FAIL, "Absent : l'URL complète peut être transmise aux sites tiers.")
    return Finding("Referrer-Policy", OK, "Présent.")


def check_permissions(headers):
    if _first(headers, "permissions-policy") is None:
        return Finding("Permissions-Policy", WARN, "Absent : pas de limitation explicite caméra, micro, géolocalisation...")
    return Finding("Permissions-Policy", OK, "Présent.")


def check_info_leaks(headers):
    leaks = []
    server = _first(headers, "server")
    if server and re.search(r"\d+\.\d+", server):
        leaks.append(f"Server: {server} (version visible)")
    if _first(headers, "x-powered-by"):
        leaks.append(f"X-Powered-By: {_first(headers, 'x-powered-by')}")
    if leaks:
        return Finding("Fuite d'informations", WARN, "Technologies et versions exposées : " + " ; ".join(leaks) + ".")
    return Finding("Fuite d'informations", OK, "Pas de version de serveur exposée.")


def check_cookies(headers):
    cookies = headers.get("set-cookie", [])
    if not cookies:
        return Finding("Cookies", OK, "Aucun cookie défini dans cette réponse.")
    problems = []
    for c in cookies:
        low = c.lower()
        name = c.split("=", 1)[0]
        missing = [flag for flag, token in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if token not in low]
        if missing:
            problems.append(f"{name} (manque {', '.join(missing)})")
    if problems:
        return Finding("Cookies", WARN, "Drapeaux manquants : " + " ; ".join(problems) + ".")
    return Finding("Cookies", OK, "Tous les cookies ont Secure, HttpOnly et SameSite.")


CHECKS = [check_hsts, check_csp, check_nosniff, check_framing, check_referrer,
          check_permissions, check_info_leaks, check_cookies]


def audit(text: str) -> list:
    headers = parse_headers(text)
    return [check(headers) for check in CHECKS]


def score(findings: list) -> int:
    """Note sur 100 : OK = 1 point, ATTENTION = 0,5 point, MANQUANT = 0."""
    points = sum({OK: 1.0, WARN: 0.5, FAIL: 0.0}[f.status] for f in findings)
    return round(100 * points / len(findings))


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit hors ligne des en-têtes de sécurité HTTP.")
    parser.add_argument("file", nargs="?", help="fichier d'en-têtes (sinon : entrée standard)")
    args = parser.parse_args()
    text = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    findings = audit(text)
    for f in findings:
        print(f"[{f.status:<9}] {f.header}: {f.message}")
    print(f"\nNote : {score(findings)}/100")
    return 0 if all(f.status == OK for f in findings) else 1


if __name__ == "__main__":
    sys.exit(main())
