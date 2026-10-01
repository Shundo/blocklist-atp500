#!/usr/bin/env python3
"""
Genera blocklist.txt per l'External Block List dell'URL Threat Filter
del firewall Zyxel ATP500, a partire dai dati di ViewDB.

Il file prodotto contiene esclusivamente nomi di dominio, uno per riga,
senza commenti e senza righe vuote: l'apparato rifiuta l'intero file se
anche una sola voce risulta malformata.

Tre idee reggono lo script, tutte nate dai dati osservati.

1. La lista e CUMULATIVA. Un dominio non esce perche il tracker smette di
   seguirlo: il 1 ottobre 2026, dei 21 domini usciti dalla lista in diciotto
   giorni, 19 rispondevano ancora, quasi tutti reindirizzando al dominio
   nuovo, e quattro servivano ancora contenuti. Un dominio esce soltanto dopo
   GIORNI_CONSERVAZIONE giorni in cui non risulta ne nel tracker ne vivo.
   Tenere in lista un dominio morto non costa nulla.

2. I portali rivelano da se il dominio nuovo. Ogni notte si interrogano i
   domini noti e si segue il reindirizzamento: se porta a un dominio dello
   STESSO MARCHIO, quello entra in lista anche se il tracker non lo conosce.
   Cosi sono emersi tanti-film.casa e cineblog01.casa, che ViewDB non segue
   piu. Il vincolo dello stesso marchio impedisce che un reindirizzamento
   verso un motore di ricerca o una pagina di parcheggio finisca in lista.

3. Un guasto della sorgente non ferma nulla. Con la lista cumulativa un
   tracker che si svuota non toglie niente, quindi lo script segnala e
   prosegue senza far fallire il workflow. Rifiuta invece di AGGIUNGERE cio
   che ha l'aria di un inquinamento: domini della pubblica amministrazione,
   delle piattaforme legali, o crescite esplosive.

File prodotti: blocklist.txt per l'apparato, registro.json con lo stato
(prima e ultima volta che ciascun dominio e stato visto, e da quale fonte),
ultimo-controllo.txt come indicatore di salute leggibile da una persona.

Non richiede dipendenze esterne: usa solo la libreria standard.
"""

import concurrent.futures
import datetime
import difflib
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ENDPOINT = "https://domains-tracker.server66.workers.dev/status"
CARTELLA = Path(__file__).resolve().parent
USCITA = CARTELLA / "blocklist.txt"
REGISTRO = CARTELLA / "registro.json"
STATO = CARTELLA / "ultimo-controllo.txt"
TIMEOUT = 30

# Un dominio resta in lista finche risulta nel tracker o vivo, e per un anno
# dopo l'ultima volta in cui e stato visto.
GIORNI_CONSERVAZIONE = 365

# Interrogazione dei domini noti per scoprire i reindirizzamenti.
TIMEOUT_SONDA = 8
SONDE_PARALLELE = 16

# Sotto questa soglia il tracker e considerato guasto e il suo contributo
# viene ignorato per l'esecuzione corrente. Nulla viene tolto.
MINIMO_TRACKER = 5

# Quota massima di record illeggibili prima di sospettare un cambio di
# formato della sorgente.
QUOTA_MASSIMA_SCARTI = 0.25

# Guardia contro l'inquinamento: oltre questo numero di domini nuovi in una
# sola esecuzione le aggiunte vengono rifiutate. ATP_ACCETTA_VARIAZIONE=1
# sblocca consapevolmente una singola esecuzione.
MASSIMO_NUOVI = 25

# Tetto della lista pubblicata, molto al di sotto delle 50.000 voci accettate
# dall'apparato.
MASSIMO_ASSOLUTO = 5000

# Somiglianza minima fra le etichette di due domini perche il secondo sia
# considerato lo stesso marchio del primo.
SIMILARITA_MINIMA = 0.85

# Domini che non devono MAI comparire in block list, confrontati per
# suffisso: "gov.it" copre ogni sottodominio. Se la sorgente ne restituisce
# uno, il contributo della sorgente viene rifiutato; se lo indica un
# reindirizzamento, quel solo reindirizzamento viene ignorato.
INTOCCABILI = (
    # Ministero e servizi pubblici
    # Pubblica amministrazione per suffisso: copre ministeri, agenzie e
    # tutto cio che sta sotto gov.it ed edu.it.
    "gov.it",
    "edu.it",
    "pa.it",
    "inps.it",
    "istruzione.it",
    "miur.it",
    "mim.gov.it",
    "indire.it",
    "invalsi.it",
    "agid.gov.it",
    "spid.gov.it",
    # Registri elettronici: tutti i principali, domini verificati il 1/10/2026
    # risolvendoli e leggendo le pagine di accesso. classeviva.it non esiste:
    # ClasseViva sta interamente su spaggiari.eu.
    "madisoft.it",            # Nuvola
    "scuoladigitale.info",    # Nuvola, risorse della pagina di accesso
    "argosoft.it",            # Argo
    "portaleargo.it",         # Argo
    "argofamiglia.it",        # Argo, area famiglie
    "registroelettronico.app",  # Argo
    "campusargo.it",          # Argo
    "spaggiari.eu",           # Spaggiari ClasseViva
    "axioscloud.it",          # Axios
    "axiositalia.it",         # Axios
    "registroelettronico.com",  # Mastercom
    "mastercom.it",           # Mastercom
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

# Piattaforme di streaming LEGALE: sulla rete Wi-Fi devono restare
# raggiungibili, e la lista esterna si applica a entrambe le reti.
INTOCCABILI = INTOCCABILI + (
    "primevideo.com",
    "amazon.com",
    "amazon.it",
    "media-amazon.com",
    "aiv-cdn.net",
    "aiv-delivery.net",
    "netflix.com",
    "nflxvideo.net",
    "nflximg.net",
    "nflxso.net",
    "nflxext.com",
    "disneyplus.com",
    "disney-plus.net",
    "bamgrid.com",
    "mediaset.it",
    "mediasetinfinity.it",
    "la7.it",
    "sky.it",
    "nowtv.it",
    "now.tv",
    "dazn.com",
    "timvision.it",
    "paramountplus.com",
    "twitch.tv",
    "spotify.com",
)

# Comuni, province e regioni non hanno un suffisso comune: usano lo schema
# comune.<nome>.<sigla>.it, provincia.<nome>.it, regione.<nome>.it. Si
# riconoscono dall'etichetta iniziale, ristretta ai domini .it perche fuori da
# quel suffisso la stessa parola non indica un ente italiano.
PREFISSI_ENTI_LOCALI = ("comune.", "provincia.", "regione.", "citta.", "cittametropolitana.")

VALIDI = set("abcdefghijklmnopqrstuvwxyz0123456789-.")


class Guasto(Exception):
    """Il contributo del tracker non e affidabile in questa esecuzione."""


# --------------------------------------------------------------------------
# Utilita
# --------------------------------------------------------------------------

def adesso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def oggi() -> str:
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def giorni_da(data: str) -> int:
    return (datetime.date.fromisoformat(oggi()) - datetime.date.fromisoformat(data)).days


def avviso(messaggio: str) -> None:
    """Un avviso visibile senza far fallire il workflow."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::warning::{messaggio}")
    print(f"ATTENZIONE: {messaggio}", file=sys.stderr)


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
    if not host or len(host) > 253 or set(host) - VALIDI:
        return None
    etichette = host.split(".")
    if len(etichette) < 2:
        return None
    for etichetta in etichette:
        if not etichetta or len(etichetta) > 63:
            return None
        if etichetta.startswith("-") or etichetta.endswith("-"):
            return None
    if etichette[-1].isdigit():
        return None
    return host


def intoccabile(dominio: str) -> str | None:
    """Restituisce il dominio protetto corrispondente, se c'e."""
    for protetto in INTOCCABILI:
        if dominio == protetto or dominio.endswith("." + protetto):
            return protetto
    if dominio.endswith(".it"):
        for prefisso in PREFISSI_ENTI_LOCALI:
            if dominio.startswith(prefisso) or ("." + prefisso) in dominio:
                return prefisso + "*.it"
    return None


def marchio(dominio: str) -> str:
    """L'etichetta che porta il marchio: quella prima del suffisso."""
    parti = dominio.split(".")
    return parti[-2] if len(parti) >= 2 else dominio


def stesso_marchio(a: str, b: str) -> bool:
    """Vero se i due domini portano lo stesso marchio con un altro suffisso.

    altadefinizione.fast e altadefinizionex.me si', perche un'etichetta
    contiene l'altra; tanti-film.beer e tanti-film.casa si'; tanti-film.beer
    e un motore di ricerca no.
    """
    x = marchio(a).replace("-", "")
    y = marchio(b).replace("-", "")
    if len(x) < 5 or len(y) < 5:
        return False
    if x in y or y in x:
        return True
    return difflib.SequenceMatcher(None, x, y).ratio() >= SIMILARITA_MINIMA


# --------------------------------------------------------------------------
# Registro
# --------------------------------------------------------------------------

def carica_registro() -> dict:
    if REGISTRO.exists():
        return json.loads(REGISTRO.read_text(encoding="utf-8"))
    # Prima esecuzione con lo schema cumulativo: si parte dalla lista attuale.
    registro = {"domini": {}, "ultimo_tracker_riuscito": None}
    if USCITA.exists():
        for riga in USCITA.read_text(encoding="utf-8").splitlines():
            dominio = normalizza(riga.strip())
            if dominio:
                registro["domini"][dominio] = {"primo": oggi(), "ultimo": oggi(), "fonte": "lista precedente"}
    return registro


def salva_registro(registro: dict) -> None:
    registro["domini"] = dict(sorted(registro["domini"].items()))
    REGISTRO.write_text(
        json.dumps(registro, indent=1, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n"
    )


# --------------------------------------------------------------------------
# Tracker
# --------------------------------------------------------------------------

def scarica() -> dict:
    req = urllib.request.Request(
        ENDPOINT,
        headers={"User-Agent": "atp500-blocklist/2.0", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as risposta:
        return json.loads(risposta.read().decode("utf-8"))


def estrai_tracker(dati) -> set[str]:
    """I domini correnti del tracker, oppure Guasto se non sono affidabili."""
    if not isinstance(dati, dict) or not dati:
        raise Guasto("risposta vuota o di formato inatteso")
    domini, scartati = set(), 0
    for valori in dati.values():
        dominio = normalizza(valori.get("full_url", "")) if isinstance(valori, dict) else None
        if dominio:
            domini.add(dominio)
        else:
            scartati += 1
    if scartati / len(dati) > QUOTA_MASSIMA_SCARTI:
        raise Guasto(f"{scartati} record illeggibili su {len(dati)}: probabile cambio di formato")
    if len(domini) < MINIMO_TRACKER:
        raise Guasto(f"solo {len(domini)} domini, sotto il minimo di {MINIMO_TRACKER}")
    protetti = sorted(d for d in domini if intoccabile(d))
    if protetti:
        raise Guasto(f"restituiti domini protetti: {', '.join(protetti)}")
    return domini


# --------------------------------------------------------------------------
# Sonde: chi e vivo, e dove reindirizza
# --------------------------------------------------------------------------

# La verifica dei certificati e disattivata DI PROPOSITO e solo qui: i
# portali usano spesso certificati irregolari, e alla sonda non interessa il
# contenuto, che non viene letto, ma soltanto se il sito risponde e dove
# reindirizza.
_CONTESTO_SONDA = ssl.create_default_context()
_CONTESTO_SONDA.check_hostname = False
_CONTESTO_SONDA.verify_mode = ssl.CERT_NONE


def sonda(dominio: str) -> tuple[str, bool, str | None]:
    """Restituisce (dominio, vivo, dominio di arrivo se diverso)."""
    req = urllib.request.Request(
        f"https://{dominio}/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/130"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SONDA, context=_CONTESTO_SONDA) as r:
            arrivo = normalizza(r.geturl())
    except urllib.error.HTTPError as e:
        # Un 403 di una protezione anti-bot e un sito vivo; un 5xx no.
        return dominio, e.code < 500, None
    except Exception:
        return dominio, False, None
    if arrivo and arrivo != dominio and not arrivo.endswith("." + dominio) and not dominio.endswith("." + arrivo):
        return dominio, True, arrivo
    return dominio, True, None


def sonda_tutti(domini: list[str]) -> dict:
    with concurrent.futures.ThreadPoolExecutor(SONDE_PARALLELE) as esecutore:
        return {d: (vivo, arrivo) for d, vivo, arrivo in esecutore.map(sonda, domini)}


# --------------------------------------------------------------------------
# Aggiornamento del registro
# --------------------------------------------------------------------------

def candidati(registro: dict, tracker: set[str], sonde: dict) -> dict:
    """I domini da aggiungere o rinfrescare, con la fonte di ciascuno."""
    proposte = {d: "viewdb" for d in tracker}
    for origine, (_vivo, arrivo) in sonde.items():
        if not arrivo or arrivo in proposte:
            continue
        if not stesso_marchio(origine, arrivo):
            continue
        if intoccabile(arrivo):
            avviso(f"{origine} reindirizza al dominio protetto {arrivo}: ignorato")
            continue
        proposte[arrivo] = f"reindirizzamento da {origine}"
    return proposte


def aggiorna(registro: dict, proposte: dict, sonde: dict) -> list[str]:
    """Applica proposte e sonde al registro; restituisce i domini aggiunti."""
    domini = registro["domini"]
    nuovi = sorted(d for d in proposte if d not in domini)
    if len(nuovi) > MASSIMO_NUOVI and os.environ.get("ATP_ACCETTA_VARIAZIONE") != "1":
        avviso(
            f"{len(nuovi)} domini nuovi in una sola esecuzione, oltre il limite di {MASSIMO_NUOVI}: "
            "aggiunte rifiutate per sospetto inquinamento. Se legittimo, rilanciare il workflow "
            "spuntando accetta_variazione."
        )
        nuovi = []
        proposte = {d: f for d, f in proposte.items() if d in domini}
    for dominio, fonte in proposte.items():
        voce = domini.setdefault(dominio, {"primo": oggi(), "fonte": fonte})
        voce["ultimo"] = oggi()
    for dominio, (vivo, _arrivo) in sonde.items():
        if vivo and dominio in domini:
            domini[dominio]["ultimo"] = oggi()
    return nuovi


def pubblicabili(registro: dict) -> tuple[list[str], list[str]]:
    """La lista da pubblicare, e i domini scaduti che ne escono."""
    tenuti, scaduti = [], []
    for dominio, voce in registro["domini"].items():
        if giorni_da(voce["ultimo"]) > GIORNI_CONSERVAZIONE:
            scaduti.append(dominio)
        elif normalizza(dominio) == dominio and not intoccabile(dominio):
            # Ricontrollati a ogni esecuzione: se l'elenco dei domini protetti
            # viene esteso, un dominio gia in registro esce subito dalla lista.
            tenuti.append(dominio)
    for dominio in scaduti:
        del registro["domini"][dominio]
    if len(tenuti) > MASSIMO_ASSOLUTO:
        avviso(f"{len(tenuti)} domini, oltre il tetto di {MASSIMO_ASSOLUTO}: pubblicati i piu recenti")
        tenuti.sort(key=lambda d: registro["domini"][d]["ultimo"], reverse=True)
        tenuti = tenuti[:MASSIMO_ASSOLUTO]
    return sorted(tenuti), sorted(scaduti)


# --------------------------------------------------------------------------
# Uscite
# --------------------------------------------------------------------------

def scrivi_uscite(lista: list[str], registro: dict, esito_tracker: str) -> None:
    # Il parametro newline e obbligatorio: su Windows write_text tradurrebbe i
    # fine riga in CRLF e il ritorno a capo renderebbe malformata ogni voce,
    # facendo rifiutare all'apparato l'intero file.
    USCITA.write_text("\n".join(lista) + "\n", encoding="utf-8", newline="\n")
    salva_registro(registro)
    STATO.write_text(
        f"ultimo-controllo: {adesso()}\n"
        f"esito-tracker: {esito_tracker}\n"
        f"ultimo-tracker-riuscito: {registro.get('ultimo_tracker_riuscito') or 'mai'}\n"
        f"domini-pubblicati: {len(lista)}\n"
        f"sorgente: {ENDPOINT}\n",
        encoding="utf-8",
        newline="\n",
    )


def riassunto(lista: list[str], nuovi: list[str], scaduti: list[str], esito: str, fonti: dict) -> None:
    righe = [
        f"Domini pubblicati: {len(lista)}",
        f"Tracker: {esito}",
    ]
    if nuovi:
        righe.append("Nuovi: " + ", ".join(f"{d} ({fonti.get(d, '?')})" for d in nuovi))
    if scaduti:
        righe.append("Scaduti dopo un anno senza segni di vita: " + ", ".join(scaduti))
    print("\n".join(righe))
    file_riassunto = os.environ.get("GITHUB_STEP_SUMMARY")
    if file_riassunto:
        with open(file_riassunto, "a", encoding="utf-8") as fh:
            fh.write("## Aggiornamento della blocklist\n\n" + "\n\n".join(righe) + "\n")


def main() -> int:
    registro = carica_registro()

    try:
        tracker = estrai_tracker(scarica())
        esito = f"ok, {len(tracker)} domini"
        registro["ultimo_tracker_riuscito"] = adesso()
    except Guasto as motivo:
        tracker, esito = set(), f"ERRORE: {motivo}"
        avviso(f"tracker ignorato in questa esecuzione ({motivo}). La lista resta quella cumulativa.")
    except Exception as errore:
        tracker, esito = set(), f"ERRORE: irraggiungibile ({type(errore).__name__})"
        avviso(f"tracker irraggiungibile ({errore}). La lista resta quella cumulativa.")

    sonde = sonda_tutti(sorted(set(registro["domini"]) | tracker))
    proposte = candidati(registro, tracker, sonde)
    nuovi = aggiorna(registro, proposte, sonde)
    lista, scaduti = pubblicabili(registro)

    scrivi_uscite(lista, registro, esito)
    riassunto(lista, nuovi, scaduti, esito, proposte)
    return 0


if __name__ == "__main__":
    sys.exit(main())
