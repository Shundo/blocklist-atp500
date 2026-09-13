#!/usr/bin/env python3
"""
Genera blocklist.txt per l'External Block List dell'URL Threat Filter
del firewall Zyxel ATP500, a partire dai dati di ViewDB.

Il file prodotto contiene esclusivamente nomi di dominio, uno per riga,
senza commenti e senza righe vuote: l'apparato rifiuta l'intero file se
anche una sola voce risulta malformata.

Non richiede dipendenze esterne: usa solo la libreria standard.
"""

import json
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ENDPOINT = "https://domains-tracker.server66.workers.dev/status"
USCITA = Path(__file__).resolve().parent / "blocklist.txt"
TIMEOUT = 30
MINIMO_ATTESO = 5  # sotto questa soglia si sospetta un guasto della sorgente

VALIDI = set("abcdefghijklmnopqrstuvwxyz0123456789-.")


def scarica() -> dict:
    req = urllib.request.Request(
        ENDPOINT,
        headers={"User-Agent": "atp500-blocklist/1.0", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as risposta:
        return json.loads(risposta.read().decode("utf-8"))


def normalizza(url: str) -> str | None:
    if not url:
        return None
    if "://" not in url:
        url = "https://" + url
    host = (urlparse(url).hostname or "").strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or "." not in host:
        return None
    if set(host) - VALIDI:
        return None
    if host.startswith("-") or host.endswith("-") or ".." in host:
        return None
    return host


def main() -> int:
    try:
        dati = scarica()
    except Exception as errore:
        print(f"Errore nel recupero da ViewDB: {errore}", file=sys.stderr)
        return 1

    domini = set()
    for valori in dati.values():
        if isinstance(valori, dict):
            dominio = normalizza(valori.get("full_url", ""))
            if dominio:
                domini.add(dominio)

    if len(domini) < MINIMO_ATTESO:
        print(
            f"Estratti solo {len(domini)} domini, sotto la soglia di sicurezza: "
            "il file non viene riscritto per non svuotare la block list.",
            file=sys.stderr,
        )
        return 1

    ordinati = sorted(domini)
    # Il parametro newline e obbligatorio: su Windows write_text tradurrebbe i fine
    # riga in CRLF e il ritorno a capo renderebbe malformata ogni voce, facendo
    # rifiutare all'apparato l'intero file (importazione di tipo tutto o niente).
    USCITA.write_text("\n".join(ordinati) + "\n", encoding="utf-8", newline="\n")
    print(f"Scritti {len(ordinati)} domini in {USCITA.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
