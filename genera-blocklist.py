#!/usr/bin/env python3
"""
Genera blocklist.txt per l'External Block List dell'URL Threat Filter
del firewall Zyxel ATP500, a partire dai dati di ViewDB.

Il file prodotto contiene esclusivamente nomi di dominio, uno per riga,
senza commenti e senza righe vuote: l'apparato rifiuta l'intero file se
anche una sola voce risulta malformata.

Il contenuto di questo file finisce in una configurazione di sicurezza
senza revisione umana, a partire da un endpoint di terzi che non
controlliamo. Le salvaguardie sotto servono a questo: rifiutare
l'aggiornamento e lasciare intatta la lista precedente e sempre
preferibile a scrivere una lista sbagliata, perche una lista vecchia
blocca ancora, mentre una lista dimezzata no e una lista inquinata
blocca la didattica.

Non richiede dipendenze esterne: usa solo la libreria standard.
"""

import datetime
import json
import os
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ENDPOINT = "https://domains-tracker.server66.workers.dev/status"
USCITA = Path(__file__).resolve().parent / "blocklist.txt"
STATO = Path(__file__).resolve().parent / "ultimo-controllo.txt"
TIMEOUT = 30

# Pavimento assoluto. Vale da solo unicamente alla prima esecuzione, quando
# non esiste ancora una lista precedente con cui confrontarsi.
MINIMO_ASSOLUTO = 5

# Tetto esplicito, molto al di sotto delle 50.000 voci accettate
# dall'apparato: oltre questo numero si e certamente davanti a un guasto
# della sorgente e non a una crescita reale del fenomeno.
MASSIMO_ASSOLUTO = 5000

# Soglie relative all'esecuzione precedente. Sono la protezione vera: la
# costante assoluta non distingue 8 domini su 18 da 18 su 18.
#
# Hanno pero un rovescio da conoscere: se la sorgente cambiasse in modo
# duraturo e legittimo, per esempio perdendo meta delle testate monitorate,
# il rifiuto diventerebbe permanente e la lista resterebbe ferma per sempre,
# perche la base del confronto non avanza mai. Un aggiornamento sbagliato si
# vede, uno mancato no. Da qui due contromisure: ultimo-controllo.txt, la cui
# data smette di avanzare e rende visibile lo stallo, e la variabile d'ambiente
# qui sotto, che consente di sbloccare consapevolmente una singola esecuzione
# dopo aver verificato a mano che la lista nuova sia buona.
#
#     ATP_ACCETTA_VARIAZIONE=1 python3 genera-blocklist.py
#
# Le protezioni che non vanno mai aggirate, cioe il pavimento assoluto, il
# tetto e i domini intoccabili, restano attive anche in quel caso.
QUOTA_MINIMA_SU_PRECEDENTE = 0.80
FATTORE_MASSIMO_CRESCITA = 2.0

# Quota massima di record che l'endpoint puo restituire in forma
# inutilizzabile prima che si sospetti un cambio di formato anziche
# qualche voce sporca.
QUOTA_MASSIMA_SCARTI = 0.25

# Domini che non devono MAI comparire in block list. Se la sorgente ne
# restituisce uno, si e davanti a un guasto o a un avvelenamento e lo
# script si ferma senza toccare nulla. Il confronto e per suffisso, quindi
# "istruzione.it" copre anche "www.istruzione.it" e i sottodomini.
# Da estendere con i servizi effettivamente in uso nell'istituto.
INTOCCABILI = (
    # Ministero e servizi pubblici
    "istruzione.it",
    "miur.it",
    "mim.gov.it",
    "indire.it",
    "invalsi.it",
    "agid.gov.it",
    "spid.gov.it",
    # Registri elettronici piu diffusi
    "madisoft.it",
    "nuvola.madisoft.it",
    "argosoft.it",
    "portaleargo.it",
    "spaggiari.eu",
    "classeviva.it",
    "axioscloud.it",
    "axiositalia.it",
    # Piattaforme didattiche e identita
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "classroom.google.com",
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "office365.com",
    "live.com",
    "sharepoint.com",
    "zoom.us",
    "webex.com",
    # Eccezioni didattiche dichiarate dal progetto
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "googlevideo.com",
    "ggpht.com",
    "youtube-nocookie.com",
    "rai.it",
    "raiplay.it",
    "raiplaysound.it",
    "rai.tv",
)

VALIDI = set("abcdefghijklmnopqrstuvwxyz0123456789-.")


class Guasto(Exception):
    """Condizione che impone di NON riscrivere la lista."""


def scarica() -> dict:
    req = urllib.request.Request(
        ENDPOINT,
        headers={"User-Agent": "atp500-blocklist/1.0", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as risposta:
        return json.loads(risposta.read().decode("utf-8"))


def normalizza(url: str) -> str | None:
    """Da una URL al nome di dominio, o None se non e utilizzabile.

    La validazione e deliberatamente severa: una sola voce malformata fa
    rifiutare all'apparato l'INTERO file, quindi conviene perdere un
    dominio buono piuttosto che far passare una voce dubbia.
    """
    if not url or not isinstance(url, str):
        return None
    if "://" not in url:
        url = "https://" + url
    try:
        host = (urlparse(url).hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return None
    if host.startswith("www."):
        host = host[4:]
    if not host or len(host) > 253:
        return None
    if set(host) - VALIDI:
        return None
    etichette = host.split(".")
    if len(etichette) < 2:
        return None
    for etichetta in etichette:
        # Ogni etichetta deve essere non vuota, lunga al massimo 63 caratteri
        # e non puo iniziare ne finire con un trattino. Il controllo va fatto
        # etichetta per etichetta: "foo.-bar.com" supererebbe un controllo
        # applicato al solo nome intero.
        if not etichetta or len(etichetta) > 63:
            return None
        if etichetta.startswith("-") or etichetta.endswith("-"):
            return None
    # Il dominio di primo livello non puo essere tutto numerico: scarta gli
    # indirizzi IP, che nella External Block List non hanno senso.
    if etichette[-1].isdigit():
        return None
    return host


def intoccabile(dominio: str) -> str | None:
    """Restituisce il dominio protetto corrispondente, se c'e."""
    for protetto in INTOCCABILI:
        if dominio == protetto or dominio.endswith("." + protetto):
            return protetto
    return None


def estrai(dati) -> tuple[set[str], int, int]:
    """Restituisce (domini, record letti, record scartati)."""
    if not isinstance(dati, dict):
        raise Guasto(
            f"La sorgente ha restituito {type(dati).__name__} invece di un oggetto: "
            "formato cambiato."
        )
    if not dati:
        raise Guasto("La sorgente ha restituito un oggetto vuoto.")

    domini: set[str] = set()
    letti = 0
    scartati = 0
    for testata, valori in dati.items():
        letti += 1
        if not isinstance(valori, dict):
            scartati += 1
            continue
        dominio = normalizza(valori.get("full_url", ""))
        if dominio:
            domini.add(dominio)
        else:
            scartati += 1
            print(f"  scartato: {testata} -> {valori.get('full_url', '(assente)')!r}", file=sys.stderr)
    return domini, letti, scartati


def carica_precedente() -> set[str]:
    """La lista dell'esecuzione precedente, che il checkout ha gia ripristinato."""
    if not USCITA.exists():
        return set()
    try:
        return {r.strip() for r in USCITA.read_text(encoding="utf-8").splitlines() if r.strip()}
    except OSError:
        return set()


def verifica(domini: set[str], letti: int, scartati: int, precedenti: set[str]) -> None:
    """Solleva Guasto se la lista nuova non e degna di sostituire la vecchia."""
    if letti and scartati / letti > QUOTA_MASSIMA_SCARTI:
        raise Guasto(
            f"Scartati {scartati} record su {letti} "
            f"({scartati / letti:.0%}, soglia {QUOTA_MASSIMA_SCARTI:.0%}): "
            "probabile cambio di formato della sorgente."
        )

    for dominio in sorted(domini):
        protetto = intoccabile(dominio)
        if protetto:
            raise Guasto(
                f"La sorgente ha restituito {dominio!r}, che ricade sotto il dominio "
                f"protetto {protetto!r}. Bloccarlo interromperebbe un servizio "
                "didattico: la lista non viene riscritta."
            )

    if len(domini) < MINIMO_ASSOLUTO:
        raise Guasto(
            f"Estratti solo {len(domini)} domini, sotto il pavimento assoluto "
            f"di {MINIMO_ASSOLUTO}."
        )
    if len(domini) > MASSIMO_ASSOLUTO:
        raise Guasto(
            f"Estratti {len(domini)} domini, oltre il tetto di {MASSIMO_ASSOLUTO}."
        )

    if not precedenti:
        print("Prima esecuzione: nessuna lista precedente con cui confrontarsi.")
        return

    if os.environ.get("ATP_ACCETTA_VARIAZIONE") == "1":
        # Sblocco consapevole e valido per la sola esecuzione corrente: le
        # soglie relative vengono saltate, quelle assolute no.
        print(
            "ATP_ACCETTA_VARIAZIONE=1: soglie relative ignorate per questa "
            f"esecuzione ({len(precedenti)} domini prima, {len(domini)} ora).",
            file=sys.stderr,
        )
        return

    minimo = int(len(precedenti) * QUOTA_MINIMA_SU_PRECEDENTE)
    if len(domini) < minimo:
        persi = sorted(precedenti - domini)
        raise Guasto(
            f"La lista nuova ha {len(domini)} domini contro i {len(precedenti)} "
            f"precedenti, sotto la soglia di {minimo} "
            f"({QUOTA_MINIMA_SU_PRECEDENTE:.0%}). Domini perduti: {', '.join(persi)}. "
            "La lista non viene riscritta. Se la variazione fosse legittima, "
            "verificarla a mano e rilanciare con ATP_ACCETTA_VARIAZIONE=1."
        )

    massimo = int(len(precedenti) * FATTORE_MASSIMO_CRESCITA)
    if len(domini) > massimo:
        raise Guasto(
            f"La lista nuova ha {len(domini)} domini contro i {len(precedenti)} "
            f"precedenti, oltre il massimo di {massimo}. La lista non viene riscritta. "
            "Se la variazione fosse legittima, verificarla a mano e rilanciare con "
            "ATP_ACCETTA_VARIAZIONE=1."
        )


def main() -> int:
    try:
        dati = scarica()
    except Exception as errore:
        print(f"Errore nel recupero da ViewDB: {errore}", file=sys.stderr)
        return 1

    precedenti = carica_precedente()

    try:
        domini, letti, scartati = estrai(dati)
        verifica(domini, letti, scartati, precedenti)
    except Guasto as motivo:
        print(f"AGGIORNAMENTO RIFIUTATO: {motivo}", file=sys.stderr)
        return 1
    except Exception as errore:
        print(f"Errore inatteso nell'analisi dei dati: {errore!r}", file=sys.stderr)
        return 1

    ordinati = sorted(domini)
    # Il parametro newline e obbligatorio: su Windows write_text tradurrebbe i fine
    # riga in CRLF e il ritorno a capo renderebbe malformata ogni voce, facendo
    # rifiutare all'apparato l'intero file (importazione di tipo tutto o niente).
    USCITA.write_text("\n".join(ordinati) + "\n", encoding="utf-8", newline="\n")

    # Indicatore di freschezza. Va scritto SOLO qui, cioe dopo che la lista
    # e stata accettata e riscritta: se lo script rifiuta l'aggiornamento la
    # data resta indietro, ed e proprio quello il segnale da cercare quando
    # ci si chiede se la catena sia ancora viva. Sta in un file separato
    # perche blocklist.txt non tollera righe che non siano domini.
    adesso = datetime.datetime.now(datetime.timezone.utc)
    STATO.write_text(
        "ultimo-controllo-riuscito: "
        + adesso.strftime("%Y-%m-%dT%H:%M:%SZ")
        + "\ndomini: "
        + str(len(ordinati))
        + "\nsorgente: "
        + ENDPOINT
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    nuovi = sorted(domini - precedenti)
    spariti = sorted(precedenti - domini)
    print(f"Scritti {len(ordinati)} domini in {USCITA.name} (letti {letti}, scartati {scartati})")
    if nuovi:
        print(f"Comparsi: {', '.join(nuovi)}")
    if spariti:
        print(f"Spariti: {', '.join(spariti)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
