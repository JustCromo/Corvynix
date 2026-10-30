"""CLOUD - riceve le righe cifrate, le decifra e le verifica in tempo reale.

Per ogni riga mostra due giudizi indipendenti:
  INTEGRITÀ     sigillata | verificata | giallo | rosso | mancante
                - verificata: firma, chiave dell'epoca e catena ok (giudizio provvisorio)
                - sigillata:  in più l'epoca è chiusa (chiave distrutta) e il controllo
                              periodico ha confermato che la copia locale è identica
  PLAUSIBILITÀ  ok | anomalie (soglie, salti anomali, timestamp)

A fine volo la riconciliazione con il log locale rende tutto definitivo.

Avvio:  uvicorn cloud:app --port 8002
"""
import asyncio
import csv
import os
import io
import json
import statistics
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response

from common import aad_for, canon, raw_pub, record_hash, sha256_hex, unseal, verify
from detector import analyze

EXPORT_COLS = ("_missione", "_riga", "_hash")

CAPSULE = os.environ.get("CAPSULE_URL", "http://127.0.0.1:8001")
DATA_DIR = Path(__file__).parent / "data" / "cloud"
DATA_DIR.mkdir(parents=True, exist_ok=True)
clients: set[WebSocket] = set()

# La chiave privata esiste SOLO qui. La capsula conosce solo la pubblica.
PRIV = X25519PrivateKey.generate()
PUB_HEX = raw_pub(PRIV.public_key()).hex()

GREEN = ("sigillata", "verificata")
TIME_HINTS = ("time", "date", "timestamp", "stamp")
TIME_EXACT = ("t_s", "t", "ts", "tempo", "tempo_s")
SILENCE_S = 5


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ct_hash(env: dict) -> str:
    return sha256_hex(env["box"]["ct"].encode())


def is_time_col(c: str) -> bool:
    return c.lower() in TIME_EXACT or any(h in c.lower() for h in TIME_HINTS)


def num(v):
    try:
        return float(str(v).replace(",", "."))
    except (TypeError, ValueError):
        return None


def tval(v):
    x = num(v)
    if x is not None:
        return x
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


class Store:
    def __init__(self):
        self.reset()

    def reset(self):
        self.mission: dict | None = None
        self.pubs: list[bytes] = []
        self.versions: dict[int, list[dict]] = {}
        self.accepted: dict[int, dict] = {}
        self.evidence: list[dict] = []
        self.events: list[dict] = []
        self.last_sent: dict[int, str] = {}
        self.summary = None
        self.confirmed: set[int] = set()     # righe la cui copia locale è confermata identica
        self.max_epoch = -1                   # epoca più alta ricevuta valida
        self.ended = False
        self.limits: dict[str, dict] = {}     # regole di plausibilità per colonna
        self.plaus: dict[int, list[str]] = {}
        self.last_rx = None
        self.flow = ""
        self.audits = {"eseguiti": 0, "discrepanze": 0, "ultimo": None}
        self.examined: dict[int, str] = {}    # epoca -> impronta locale già analizzata
        self.safe = None                      # safe mode in corso (dalla capsula)
        self.safe_log: list[dict] = []        # storico delle safe mode della missione
        self.watch: list[dict] = []           # andamento dello spostamento non spiegato
        self.flagged: set[int] = set()        # righe con discrepanza già segnalata

    @property
    def epoch_size(self) -> int:
        return self.mission["epoch_size"] if self.mission else 10

    @property
    def compromised_epoch(self):
        eps = [e["epoch"] for e in self.evidence if e["epoch"] is not None]
        return min(eps) if eps else None


st = Store()


# ---------------- comunicazione con la dashboard ----------------

async def broadcast(msg: dict):
    dead = []
    for ws in clients:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


async def event(text: str, kind: str = "info"):
    ev = {"t": time.strftime("%H:%M:%S"), "kind": kind, "text": text}
    st.events.append(ev)
    await broadcast({"type": "event", **ev})


def add_evidence(epoch, seq, why):
    if not any(e["epoch"] == epoch and e["seq"] == seq and e["why"] == why for e in st.evidence):
        st.evidence.append({"epoch": epoch, "seq": seq, "why": why})


# ---------------- verifica crittografica ----------------

def open_envelope(env: dict, source: str) -> dict:
    seq = int(env.get("seq", -1))
    v = {"seq": seq, "source": source, "at": now_iso(), "ok": False, "why": "", "rec": None,
         "hash": None, "key_epoch": None, "ct": ct_hash(env)}
    try:
        payload = json.loads(unseal(PRIV, env["box"], aad_for(st.mission["id"], seq)))
    except Exception:
        v["why"] = "non decifrabile: busta alterata"
        return v
    rec, h, sig = payload["rec"], payload["hash"], payload["sig"]
    v["rec"], v["hash"] = rec, h
    if record_hash(rec) != h or rec.get("seq") != seq:
        v["why"] = "hash non corrisponde al contenuto"
        return v
    expected = seq // st.epoch_size
    signer = next((i for i, p in enumerate(st.pubs) if verify(p, sig, h)), None)
    if signer is None:
        v["why"] = "firma non valida"
        return v
    v["key_epoch"] = signer
    if signer != expected:
        v["why"] = f"firmata con la chiave dell'epoca {signer}, attesa {expected}"
        add_evidence(signer, seq, f"riga #{seq} riscritta con la chiave dell'epoca {signer}")
        return v
    v["ok"] = True
    return v


def admit(v: dict) -> str:
    seq = v["seq"]
    st.versions.setdefault(seq, []).append(v)
    if not v["ok"]:
        return "invalida"
    acc = st.accepted.get(seq)
    if acc is None:
        st.accepted[seq] = v
        st.max_epoch = max(st.max_epoch, seq // st.epoch_size)
        if v["rec"]["type"] == "END":
            st.ended = True
        recompute_plaus(seq, seq + 1)
        return "nuova"
    if acc["hash"] == v["hash"]:
        return "coincide"
    add_evidence(v["key_epoch"], seq, f"doppia versione firmata della riga #{seq}")
    return "conflitto"


# ---------------- plausibilità ----------------

def data_of(seq):
    a = st.accepted.get(seq)
    return a["rec"]["data"] if a and a["rec"]["type"] == "DATA" else None


def plaus_for(seq: int) -> list[str]:
    d = data_of(seq)
    if d is None:
        return []
    out = []
    for col, lim in st.limits.items():
        if not lim.get("on", True) or col not in d:
            continue
        v = num(d[col])
        if v is None:
            continue
        if lim.get("min") is not None and v < lim["min"]:
            out.append(f"{col} {v:g} sotto il minimo {lim['min']:g}")
        if lim.get("max") is not None and v > lim["max"]:
            out.append(f"{col} {v:g} sopra il massimo {lim['max']:g}")
    p = data_of(seq - 1)
    if p is None:
        return out
    # se il CSV ha una colonna di fase/modalità, la storia per i salti vale solo dentro la stessa fase
    mcol = next((c for c in d if c.lower().startswith(("modalita", "mode", "fase", "stato_volo"))), None)
    mode = d.get(mcol) if mcol else None
    mode_change = mcol is not None and p.get(mcol) != mode
    for col, raw in d.items():
        lim = st.limits.get(col, {})
        if not lim.get("on", True):
            continue
        if is_time_col(col):
            a, b = tval(p.get(col)), tval(raw)
            if a is not None and b is not None and b <= a:
                out.append(f"{col} non crescente rispetto alla riga precedente")
            continue
        v, pv = num(raw), num(p.get(col))
        if v is None or pv is None or (mode_change and lim.get("jump") is None):
            continue
        delta = abs(v - pv)
        thr = lim.get("jump")
        if thr is None:
            hist, vals = [], []
            for s in range(seq - 1, max(-1, seq - 121), -1):
                a, b = data_of(s), data_of(s - 1)
                if a is None or num(a.get(col)) is None or (mcol and a.get(mcol) != mode):
                    break
                if b is not None and mcol and b.get(mcol) != mode:
                    b = None
                vals.append(num(a[col]))
                if b is not None and num(b.get(col)) is not None and len(hist) < 30:
                    hist.append(abs(num(a[col]) - num(b[col])))
            if len(hist) < 8:
                continue
            if all(float(x).is_integer() for x in vals):
                continue          # colonne intere (contatori, stati): niente salti automatici
            med = statistics.median(hist)
            mad = statistics.median(abs(h - med) for h in hist)
            spread = max(vals) - min(vals)
            thr = max(10 * 1.4826 * mad, 4 * med, 4 * statistics.mean(hist), 0.25 * spread, 1e-9)
        if delta > thr:
            out.append(f"salto anomalo di {col}: {pv:g} → {v:g}")
    return out


def recompute_plaus(start: int, end: int):
    for s in range(max(0, start), end + 1):
        if s in st.accepted:
            st.plaus[s] = plaus_for(s)


# ---------------- classificazione ----------------

def classify(seq: int) -> dict:
    vs = st.versions.get(seq, [])
    acc = st.accepted.get(seq)
    epoch = seq // st.epoch_size
    shown = acc or next((x for x in vs if x["rec"]), None)
    base = {
        "seq": seq, "epoch": epoch,
        "data": shown["rec"]["data"] if shown else None,
        "type": shown["rec"]["type"] if shown else None,
        "ts": shown["rec"]["ts"] if shown else None,
        "hash": acc["hash"] if acc else None,
        "source": acc["source"] if acc else (vs[0]["source"] if vs else None),
        "versions": len(vs),
        "plaus": st.plaus.get(seq, []),
        "alerts": (acc or shown or {}).get("rec", {}).get("alerts", []) if (acc or shown) else [],
    }
    if not vs:
        return {**base, "status": "mancante", "why": "non ancora ricevuta"}
    reasons, notes = [], []
    if acc is None:
        reasons += sorted({x["why"] for x in vs})
    else:
        for x in vs:
            if not x["ok"]:
                notes.append(f"copia {x['source']} alterata e respinta ({x['why']})")
            elif x["hash"] != acc["hash"]:
                reasons.append(f"esistono versioni diverse firmate (copia {x['source']})")
        prev_hash = st.mission["genesis"] if seq == 0 else (st.accepted.get(seq - 1) or {}).get("hash")
        if prev_hash and acc["rec"]["prev"] != prev_hash:
            reasons.append("catena interrotta con la riga precedente")
    if notes:
        base["tampered_copy"] = True
    if reasons:
        return {**base, "status": "rosso", "why": "; ".join(dict.fromkeys(reasons))}

    ce = st.compromised_epoch
    extra = ("; " + "; ".join(dict.fromkeys(notes))) if notes else ""
    if ce is not None and epoch > ce:
        return {**base, "status": "rosso", "why": f"firmata dopo la compromissione (chiavi dall'epoca {ce} rubate)"}
    if ce is not None and epoch == ce:
        return {**base, "status": "giallo", "why": f"integra, ma firmata con la chiave dell'epoca {ce}, poi compromessa{extra}"}

    closed = st.ended or epoch < st.max_epoch
    if closed and seq in st.confirmed and not notes:
        return {**base, "status": "sigillata", "why": "epoca chiusa e copia locale confermata identica"}
    pending = []
    if not closed:
        pending.append("epoca ancora aperta")
    if seq not in st.confirmed and not notes:
        pending.append("copia locale non ancora confermata")
    why = "firma, epoca e catena verificate" + (" (" + ", ".join(pending) + ")" if pending else "") + extra
    return {**base, "status": "verificata", "why": why}


def all_seqs() -> list[int]:
    exp = st.mission["rows_expected"] if st.mission else 0
    return list(range(max(exp, max(st.versions.keys(), default=-1) + 1)))


async def push_rows():
    changed = []
    for s in all_seqs():
        row = classify(s)
        j = json.dumps(row, sort_keys=True)
        if st.last_sent.get(s) != j:
            st.last_sent[s] = j
            changed.append(row)
    if changed:
        await broadcast({"type": "rows", "rows": changed, "compromised_epoch": st.compromised_epoch,
                         "audits": st.audits})


def counts() -> dict:
    c = {"sigillata": 0, "verificata": 0, "giallo": 0, "rosso": 0, "mancante": 0}
    for s in all_seqs():
        c[classify(s)["status"]] += 1
    return c


def save_server_copy():
    if not st.mission:
        return
    out = DATA_DIR / f"{st.mission['id']}.json"
    out.write_text(json.dumps({"mission": st.mission, "rows": [classify(s) for s in all_seqs()],
                               "evidence": st.evidence, "summary": st.summary}, indent=1, ensure_ascii=False))


def init_msg():
    return {"type": "init", "mission": st.mission, "pub": PUB_HEX, "events": st.events[-80:],
            "summary": st.summary, "compromised_epoch": st.compromised_epoch, "limits": st.limits,
            "audits": st.audits, "flow": st.flow, "safe": st.safe, "watch": st.watch[-1500:],
            "rows": [classify(s) for s in all_seqs()] if st.mission else []}


# ---------------- sorveglianza del flusso ----------------

async def flow_watch():
    while True:
        await asyncio.sleep(1)
        if not st.mission or st.ended or st.last_rx is None:
            text = "concluso" if st.ended else ""
        else:
            gap = time.time() - st.last_rx
            text = "attivo" if gap < SILENCE_S else f"nessun dato da {int(gap)} s"
        if text != st.flow:
            if text.startswith("nessun") and not st.flow.startswith("nessun"):
                await event("Flusso interrotto: nessuna riga ricevuta dalla capsula", "warn")
            if text == "attivo" and st.flow.startswith("nessun"):
                await event("Flusso ripreso", "ok")
            st.flow = text
            await broadcast({"type": "flow", "flow": text})


@asynccontextmanager
async def lifespan(_):
    task = asyncio.create_task(flow_watch())
    yield
    task.cancel()


app = FastAPI(lifespan=lifespan)


# ---------------- API ----------------

@app.get("/")
async def index():
    return FileResponse(Path(__file__).parent / "static" / "cloud.html")


@app.get("/pubkey")
async def pubkey():
    return {"pub": PUB_HEX}


@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    await ws.send_json(init_msg())
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)


@app.post("/mission")
async def mission(body: dict):
    limits = st.limits
    st.reset()
    st.limits = limits   # le regole impostate restano valide per la missione successiva
    st.mission = {
        "id": body["mission"], "epoch_size": body["epoch_size"], "genesis": body["genesis"],
        "rows_expected": body["rows_expected"], "registered": now_iso(),
        "n_keys": len(body["epoch_pubs"]), "columns": body.get("columns", []),
    }
    st.pubs = [bytes.fromhex(p) for p in body["epoch_pubs"]]
    st.mission["keys_seal"] = sha256_hex(canon(body["epoch_pubs"]) + st.mission["registered"].encode())
    await broadcast(init_msg())
    await event(f"Missione {st.mission['id']} registrata: {len(st.pubs)} chiavi pubbliche sigillate", "ok")
    return {"ok": True}


async def after_admit(v: dict, res: str, before):
    if res == "invalida":
        await event(f"Riga #{v['seq']} respinta ({v['source']}): {v['why']}", "bad")
    elif res == "conflitto":
        await event(f"Riga #{v['seq']}: seconda versione diversa firmata con la chiave giusta", "bad")
    if res == "nuova":
        rec = v["rec"]
        if rec.get("watch"):
            p = {"t": rec["watch"].get("t"), "m": rec["watch"].get("accumulo_m"),
                 "c": rec["watch"].get("concordanza_pct"), "l": rec["watch"].get("livello"), "seq": rec["seq"]}
            st.watch.append(p)
            await broadcast({"type": "watch", "p": p})
        if rec["type"] == "SAFE_MODE":
            st.safe = {**rec["data"], "riga": rec["seq"], "dal": time.strftime("%H:%M:%S")}
            st.safe_log.append(dict(st.safe))
            await event(f"SAFE MODE dalla capsula (riga #{rec['seq']}, firmata): {rec['data']['motivo']}", "bad")
            await broadcast({"type": "safe", "safe": st.safe})
        if rec["type"] == "RESUME":
            if st.safe_log:
                st.safe_log[-1]["ripresa_riga"] = rec["seq"]
            st.safe = None
            await event(f"Volo ripreso (riga #{rec['seq']}, firmata): {rec['data']['esito']}", "ok")
            await broadcast({"type": "safe", "safe": None})
    if res == "nuova" and v["rec"].get("alerts"):
        for a in v["rec"]["alerts"]:
            await event(f"Rilevatore di bordo (riga #{v['seq']}, firmato nella black box): {a['caso_label']} "
                        f"da {a['da_t']} s. {a['motivo']}", "bad")
    if res == "nuova" and st.plaus.get(v["seq"]) and not st.plaus.get(v["seq"] - 1):
        # segnala solo l'inizio di una serie di anomalie, non ogni riga
        await event(f"Riga #{v['seq']}: anomalia di plausibilità ({'; '.join(st.plaus[v['seq']])})", "warn")
    if st.compromised_epoch is not None and st.compromised_epoch != before:
        await event(f"Prova di compromissione: chiave dell'epoca {st.compromised_epoch} in mano all'attaccante. "
                    f"Epoca {st.compromised_epoch} in giallo, successive in rosso", "bad")


@app.post("/ingest")
async def ingest(body: dict):
    if not st.mission:
        return {"ok": False}
    st.last_rx = time.time()
    before = st.compromised_epoch
    v = open_envelope(body["envelope"], body.get("source", "live"))
    await after_admit(v, admit(v), before)
    await push_rows()
    return {"ok": True}


@app.post("/audit")
async def audit(body: dict):
    """Controllo periodico: la capsula manda, per ogni epoca, l'impronta dei ciphertext
    che ha nel log locale. Il cloud la confronta con quella dei ciphertext ricevuti,
    senza decifrare nulla. Se un'epoca non torna, chiede le buste di quell'epoca."""
    if not st.mission:
        return {"need": []}
    st.last_rx = time.time()
    need = []
    for e_str, info in body["roots"].items():
        e = int(e_str)
        seqs = info["seqs"]
        mine = [st.accepted[s]["ct"] for s in seqs if s in st.accepted]
        if len(mine) == len(seqs) and sha256_hex("".join(mine).encode()) == info["root"]:
            st.confirmed.update(seqs)
        elif st.examined.get(e) != info["root"]:
            need.append(e)            # impronta nuova: va analizzata
        st.examined[e] = info["root"]
    st.audits["eseguiti"] += 1
    bad_open = any(s // st.epoch_size == e for s in st.flagged for e in map(int, body["roots"]))
    st.audits["ultimo"] = {"ora": time.strftime("%H:%M:%S"), "fino_a": body.get("upto"),
                           "esito": "discrepanze" if need or bad_open else "ok"}
    if not need:
        await push_rows()
    return {"need": need}


@app.post("/audit/detail")
async def audit_detail(body: dict):
    before = st.compromised_epoch
    found = []
    for env in body["envelopes"]:
        seq = int(env["seq"])
        acc = st.accepted.get(seq)
        if acc and acc["ct"] == ct_hash(env):
            st.confirmed.add(seq)
            continue
        if any(x["ct"] == ct_hash(env) for x in st.versions.get(seq, [])):
            continue                  # questa copia è già stata analizzata
        v = open_envelope(env, "controllo")
        res = admit(v)
        if res == "nuova":
            st.confirmed.add(seq)       # era mancante: recuperata dal controllo
        elif res == "coincide":
            st.confirmed.add(seq)
        else:
            found.append(seq)
            await after_admit(v, res, before)
    found = [s for s in found if s not in st.flagged]
    st.flagged.update(found)
    if found:
        st.audits["discrepanze"] += len(found)
        await event(f"Controllo del log locale: righe {', '.join('#'+str(s) for s in found)} "
                    f"diverse da quelle ricevute. Manomissione rilevata in volo", "bad")
    await push_rows()
    return {"ok": True, "found": found}


@app.post("/limits")
async def set_limits(body: dict):
    clean = {}
    for col, lim in body.get("limits", {}).items():
        clean[col] = {"on": bool(lim.get("on", True)),
                      "min": num(lim.get("min")) if lim.get("min") not in (None, "") else None,
                      "max": num(lim.get("max")) if lim.get("max") not in (None, "") else None,
                      "jump": num(lim.get("jump")) if lim.get("jump") not in (None, "") else None}
    st.limits = clean
    if st.mission:
        recompute_plaus(0, max(st.accepted.keys(), default=0))
        n = sum(1 for s in st.accepted if st.plaus.get(s))
        await event(f"Regole di plausibilità aggiornate: {n} righe con anomalie", "info")
    await broadcast({"type": "limits", "limits": st.limits})
    await push_rows()
    return {"ok": True}


@app.post("/reconcile")
async def reconcile(body: dict):
    if not st.mission:
        return {"error": "nessuna missione"}
    stats = {"coincide": 0, "recuperata": 0, "diversa": 0, "alterata": 0}
    diffs, local_seqs = [], set()
    for env in body["log"]:
        seq = int(env["seq"])
        local_seqs.add(seq)
        before = st.accepted.get(seq)
        v = open_envelope(env, "locale")
        if v["rec"] is None or not v["ok"]:
            stats["alterata"] += 1
            st.versions.setdefault(seq, []).append(v)
            st.confirmed.discard(seq)
            diffs.append({"seq": seq, "esito": "alterata", "why": v["why"],
                          "cloud": before["rec"]["data"] if before else None,
                          "locale": v["rec"]["data"] if v["rec"] else None})
            continue
        if before is None:
            admit(v)
            st.confirmed.add(seq)
            stats["recuperata"] += 1
        elif before["hash"] == v["hash"]:
            st.confirmed.add(seq)
            stats["coincide"] += 1
        else:
            admit(v)
            st.confirmed.discard(seq)
            stats["diversa"] += 1
            diffs.append({"seq": seq, "esito": "diversa", "why": "contenuto diverso tra cloud e locale",
                          "cloud": before["rec"]["data"], "locale": v["rec"]["data"]})
    st.ended = True
    only_cloud = sorted(set(st.accepted) - local_seqs)
    recompute_plaus(0, max(st.accepted.keys(), default=0))
    await push_rows()

    c = counts()
    seqs = all_seqs()
    statuses = [classify(s)["status"] for s in seqs]
    first_bad = next((i for i, s in enumerate(statuses) if s not in GREEN), None)
    ordered = [st.accepted[s]["hash"] for s in seqs if s in st.accepted]
    seal_hash = sha256_hex("".join(ordered).encode())
    stamp = now_iso()
    anomalies = [{"seq": s, "why": "; ".join(st.plaus[s])} for s in sorted(st.plaus) if st.plaus[s]]

    if first_bad is None:
        verdict, level = "Integrità garantita su tutte le righe", "verde"
    else:
        verdict = (f"Integrità garantita sulle righe 0-{first_bad - 1}" if first_bad > 0 else "Nessuna riga garantita")
        verdict += f"; dalla #{first_bad} in poi servono verifiche"
        level = "rosso" if c["rosso"] else "giallo"

    st.summary = {
        "mission": st.mission["id"], "verdict": verdict, "level": level,
        "counts": c, "confronto": stats, "solo_cloud": only_cloud,
        "differenze": diffs[:50], "compromised_epoch": st.compromised_epoch,
        "evidence": st.evidence, "righe_totali": len(seqs), "locale_totali": len(local_seqs),
        "audits": st.audits, "anomalie": anomalies[:100], "n_anomalie": len(anomalies),
        "sigillo": seal_hash,
        "marca_temporale": {"ora": stamp, "token": sha256_hex((seal_hash + stamp).encode()),
                            "nota": "simulata: in produzione marca temporale qualificata eIDAS (RFC 3161)"},
    }
    save_server_copy()
    st.summary["safe_mode"] = st.safe_log
    st.summary["allarmi_bordo"] = [
        {"riga": sq, **a} for sq in sorted(st.accepted) for a in st.accepted[sq]["rec"].get("alerts", [])]
    save_server_copy()
    await event(f"Riconciliazione: {stats['coincide']} coincidono, {stats['recuperata']} recuperate, "
                f"{stats['diversa']} diverse, {stats['alterata']} alterate", "ok" if level == "verde" else "warn")
    await broadcast({"type": "summary", "summary": st.summary})
    return st.summary


def parse_csv(text: str) -> list[dict]:
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = [dict(r) for r in csv.DictReader(io.StringIO(text), dialect=dialect)]
    return [{k.strip(): (v or "").strip() for k, v in r.items() if k} for r in rows]


def verify_export(rows: list[dict]) -> dict:
    """Un CSV esportato dalla black box porta con sé missione, numero di riga e hash.
    Lo confronto con l'archivio sigillato del cloud: ogni riga modificata salta fuori."""
    if not rows or not all(c in rows[0] for c in EXPORT_COLS):
        return {"tipo": "csv_semplice",
                "messaggio": "CSV semplice: nessuna firma né hash, l'autenticità non è verificabile. "
                             "Si può valutare solo la coerenza dei dati."}
    mission = rows[0]["_missione"]
    arch_file = DATA_DIR / f"{mission}.json"
    if not arch_file.exists():
        return {"tipo": "export", "missione": mission, "esito": "archivio_assente",
                "messaggio": f"Export della missione {mission}, ma l'archivio sigillato non è su questo server."}
    arch = json.loads(arch_file.read_text())
    by_seq = {r["seq"]: r for r in arch["rows"]}
    modified, unknown, seen = [], [], set()
    for r in rows:
        try:
            seq = int(r["_riga"])
        except ValueError:
            unknown.append(r.get("_riga"))
            continue
        seen.add(seq)
        a = by_seq.get(seq)
        data = {k: v for k, v in r.items() if k not in EXPORT_COLS}
        if a is None or a.get("hash") != r["_hash"]:
            unknown.append(seq)
            continue
        diff = [k for k, v in data.items() if str((a.get("data") or {}).get(k, "")) != v]
        if diff:
            modified.append({"riga": seq, "campi": diff[:6],
                             "archivio": {k: (a.get("data") or {}).get(k) for k in diff[:6]},
                             "file": {k: data[k] for k in diff[:6]}})
    missing = sorted(s for s, a in by_seq.items() if a.get("type") == "DATA" and s not in seen)
    seal = (arch.get("summary") or {}).get("sigillo")
    ordered = [r["hash"] for r in sorted(arch["rows"], key=lambda x: x["seq"]) if r.get("hash")]
    seal_ok = seal == sha256_hex("".join(ordered).encode()) if seal else None
    untrusted = sorted(s for s in seen if (by_seq.get(s) or {}).get("status") not in ("sigillata", "verificata"))
    ok = not modified and not unknown and not missing and seal_ok is not False
    return {"tipo": "export", "missione": mission, "esito": "integro" if ok else "alterato",
            "righe": len(rows), "modificate": modified[:30], "n_modificate": len(modified),
            "sconosciute": unknown[:30], "mancanti": missing[:30], "n_mancanti": len(missing),
            "sigillo_ok": seal_ok, "righe_non_attendibili_in_volo": untrusted[:30],
            "n_non_attendibili": len(untrusted),
            "messaggio": "Ogni riga coincide con l'archivio sigillato." if ok else
                         "Il file non coincide con l'archivio sigillato della missione."}


@app.get("/analisi")
async def analisi_page():
    return FileResponse(Path(__file__).parent / "static" / "analisi.html")


@app.post("/analyze")
async def analyze_file(body: dict):
    rows = parse_csv(body.get("text", ""))
    if not rows:
        return {"ok": False, "error": "Il file non contiene righe leggibili"}
    integrity = verify_export(rows)
    clean = [{k: v for k, v in r.items() if k not in EXPORT_COLS} for r in rows]
    res = analyze(clean)
    res["integrity"] = integrity
    res["name"] = body.get("name", "volo.csv")
    return res


@app.get("/missions")
async def missions():
    out = []
    for f in sorted(DATA_DIR.glob("*.json"), reverse=True):
        out.append(f.stem)
    return {"missions": out}


@app.get("/export/{mission}.csv")
async def export(mission: str):
    f = DATA_DIR / f"{Path(mission).name}.json"
    if not f.exists():
        return Response("Missione non trovata", status_code=404)
    arch = json.loads(f.read_text())
    rows = [r for r in sorted(arch["rows"], key=lambda x: x["seq"]) if r.get("type") == "DATA" and r.get("data")]
    cols = (arch["mission"].get("columns") or list(rows[0]["data"].keys())) if rows else []
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(list(cols) + list(EXPORT_COLS))
    for r in rows:
        w.writerow([r["data"].get(c, "") for c in cols] + [arch["mission"]["id"], r["seq"], r["hash"]])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{arch["mission"]["id"]}_verificabile.csv"'})


@app.post("/command/resume")
async def command_resume():
    """L'operatore della centrale prende il controllo: nella demo il volo riprende."""
    if not st.safe:
        return {"ok": False, "error": "Nessuna safe mode in corso"}
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = (await c.post(f"{CAPSULE}/resume")).json()
    except httpx.HTTPError:
        return {"ok": False, "error": "La capsula non risponde"}
    if r.get("ok"):
        await event("Centrale: comando di presa di controllo inviato alla capsula", "info")
    return r


@app.post("/reset")
async def reset():
    limits = st.limits
    st.reset()
    st.limits = limits
    await broadcast(init_msg())
    return {"ok": True}


@app.get("/logo.png")
async def logo():
    return FileResponse(Path(__file__).parent / "docs" / "logo.png", media_type="image/png")
