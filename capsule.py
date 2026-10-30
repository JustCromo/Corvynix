"""CAPSULA - simula il Raspberry nella Smart Capsule + pannello di controllo demo.

Avvio:  uvicorn capsule:app --port 8001
"""
import asyncio
import copy
import csv
import io
import json
import os
import random
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

import math

from detector import analyze
from spoofwatch import SpoofWatch
from common import build_envelope, new_signing_key, numeric_fields, raw_pub, record_hash, sha256_hex, tamper_value

CLOUD = os.environ.get("CLOUD_URL", "http://127.0.0.1:8002")
DATA_DIR = Path(__file__).parent / "data" / "capsule"
DATA_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI()
clients: set[WebSocket] = set()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Capsule:
    def __init__(self):
        self.rows: list[dict] = []
        self.csv_name = ""
        self.reset()

    def reset(self):
        self.mission_id = ""
        self.cloud_pub = b""
        self.keys: list = []          # chiavi private per epoca (None = distrutta)
        self.epoch_size = 10
        self.seq = 0
        self.prev_hash = ""
        self.state = "pronta"         # pronta | in volo | in pausa | atterrata | conclusa
        self.online = True
        self.speed = 2.0              # righe al secondo
        self.audit_every = 10         # controllo del log locale ogni N righe
        self.last_audit = ""
        self.reported: list[tuple] = []   # allarmi del rilevatore già scritti nella black box
        self.n_alerts = 0
        self.seen_rows: list[dict] = []   # righe come le "vede" la capsula (eventualmente spoofate)
        self.data_by_seq: dict[int, dict] = {}
        self.watch = SpoofWatch()
        self.watch_state: dict = {}
        self.watch_level = "ok"
        self.spoof = None                 # attacco di spoofing lento in corso
        self.safe = None                  # safe mode in corso
        self.resume_req = False
        self.resume_rows: list[int] = []
        self.local_log: list[dict] = []
        self.sent: set[int] = set()
        self.stolen: dict[int, object] = {}   # epoca -> chiave rubata
        self.forge_base: dict = {}
        self.malware_done = False
        self.summary = None
        self.last_box = ""
        self.task = None

    @property
    def log_file(self) -> Path:
        return DATA_DIR / f"{self.mission_id or 'nessuna'}.jsonl"

    def persist(self):
        with open(self.log_file, "w") as f:
            for env in self.local_log:
                f.write(json.dumps(env) + "\n")

    def snapshot(self) -> dict:
        total = len(self.rows)
        return {
            "type": "state",
            "csv": self.csv_name,
            "rows_total": total,
            "mission": self.mission_id,
            "state": self.state,
            "online": self.online,
            "seq": self.seq,
            "epoch": self.seq // self.epoch_size if self.keys else None,
            "epoch_size": self.epoch_size,
            "speed": self.speed,
            "keys": [
                "rubata" if i in self.stolen and k is not None else
                ("distrutta" if k is None else "attiva" if i == self.seq // self.epoch_size else "in attesa")
                for i, k in enumerate(self.keys)
            ],
            "local": len(self.local_log),
            "pending": len([e for e in self.local_log if e["seq"] not in self.sent]),
            "last_box": self.last_box,
            "attacker": bool(self.stolen),
            "malware": self.malware_done,
            "summary": self.summary,
            "audit_every": self.audit_every,
            "last_audit": self.last_audit,
            "alerts": self.n_alerts,
            "watch": self.watch_state,
            "spoof": ({"rate": self.spoof["rate"], "spostamento_m": round(math.hypot(self.spoof["off_e"], self.spoof["off_n"]), 1)}
                      if self.spoof else None),
            "safe": self.safe,
            "log_file": str(self.log_file) if self.mission_id else "",
        }


cap = Capsule()


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
    await broadcast({"type": "event", "t": time.strftime("%H:%M:%S"), "kind": kind, "text": text})


async def push_state():
    await broadcast(cap.snapshot())


async def send_to_cloud(env: dict, source: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(f"{CLOUD}/ingest", json={"source": source, "envelope": env})
            return r.status_code == 200
    except httpx.HTTPError:
        return False


async def flush_backlog():
    pending = [e for e in cap.local_log if e["seq"] not in cap.sent]
    if not pending:
        return
    await event(f"Segnale tornato: invio {len(pending)} righe raccolte offline", "ok")
    for env in pending:
        if not cap.online:
            return
        if await send_to_cloud(env, "recupero"):
            cap.sent.add(env["seq"])
    await run_audit()
    await push_state()


async def run_audit():
    """Manda al cloud l'impronta dei ciphertext del log locale, epoca per epoca.
    Il cloud la confronta con ciò che ha ricevuto senza decifrare nulla."""
    if not cap.online or not cap.local_log:
        return
    by_epoch: dict[int, list] = {}
    for env in sorted(cap.local_log, key=lambda x: x["seq"]):
        by_epoch.setdefault(env["seq"] // cap.epoch_size, []).append(env)
    roots = {
        e: {"root": sha256_hex("".join(sha256_hex(x["box"]["ct"].encode()) for x in envs).encode()),
            "seqs": [x["seq"] for x in envs]}
        for e, envs in by_epoch.items()
    }
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            need = (await c.post(f"{CLOUD}/audit", json={"upto": cap.seq, "roots": roots})).json().get("need", [])
            if need:
                envs = [x for e in need for x in by_epoch.get(int(e), [])]
                await event(f"Controllo del log locale: il cloud chiede le righe delle epoche {', '.join(map(str, need))}", "warn")
                await c.post(f"{CLOUD}/audit/detail", json={"envelopes": envs})
    except httpx.HTTPError:
        return
    cap.last_audit = f"{time.strftime('%H:%M:%S')} · fino alla riga {cap.seq} · " + ("discrepanze" if need else "ok")
    await push_state()


async def onboard_detector(i: int) -> list[dict]:
    """Rilevatore di bordo: analizza la telemetria raccolta finora e restituisce
    i nuovi allarmi, che verranno scritti (e firmati) dentro la riga corrente."""
    if i < 20 or i % 5:
        return []
    res = await asyncio.to_thread(analyze, cap.seen_rows[: i + 1])
    new = []
    for sgm in res.get("segments", []):
        if any(rr - 2 <= sgm["from_row"] <= rr + 6 for rr in cap.resume_rows):
            continue   # salto dovuto al ritorno del segnale vero dopo l'intervento: è atteso
        if any(c == sgm["case"] and fr - 10 <= sgm["from_row"] <= to + 10 for c, fr, to in cap.reported):
            continue
        cap.reported.append((sgm["case"], sgm["from_row"], sgm["to_row"]))
        new.append({"caso": sgm["case"], "caso_label": sgm["case_label"], "da_t": sgm["from_t"],
                    "da_riga": sgm["from_row"], "motivo": (sgm["reasons"] or [""])[0]})
    # aggiorna la fine dei segmenti già segnalati, per non ripetere lo stesso allarme
    for sgm in res.get("segments", []):
        for k, (c, fr, to) in enumerate(cap.reported):
            if c == sgm["case"] and fr - 10 <= sgm["from_row"] <= to + 10:
                cap.reported[k] = (c, fr, max(to, sgm["to_row"]))
    return new


def row_time(row: dict, i: int) -> float:
    for k in ("t_s", "t", "tempo_s"):
        if k in row:
            try:
                return float(str(row[k]).replace(",", "."))
            except ValueError:
                pass
    return i * 0.5


def _like(orig: str, value: float) -> str:
    """Scrive il numero con gli stessi decimali dell'originale."""
    dec = len(orig.split(".")[1]) if "." in orig else 0
    return f"{value:.{dec}f}"


def apply_spoof(row: dict, t: float) -> dict:
    """Simula uno spoofer di zona: sposta TUTTI i ricevitori della stessa quantità,
    con una spinta che cresce piano (rampa) fino alla velocità scelta.
    La velocità GNSS non viene toccata: è la versione semplificata della realtà,
    in cui la spinta emerge dalle innovazioni dell'EKF."""
    sp = cap.spoof
    if not sp:
        return row
    if sp["t0"] is None:
        sp["t0"] = t
    if sp["prev_t"] is not None and t > sp["prev_t"]:
        rate = sp["rate"] * min(1.0, (t - sp["t0"]) / sp["ramp"])
        dt = t - sp["prev_t"]
        sp["off_e"] += rate * dt * math.sin(math.radians(sp["ang"]))
        sp["off_n"] += rate * dt * math.cos(math.radians(sp["ang"]))
    sp["prev_t"] = t
    out = dict(row)
    for ce, cn in (("est_m", "nord_m"), ("caps_est_m", "caps_nord_m")):
        try:
            out[ce] = _like(row[ce], float(row[ce]) + sp["off_e"])
            out[cn] = _like(row[cn], float(row[cn]) + sp["off_n"])
        except (KeyError, ValueError):
            pass
    for cla, clo in (("lat", "lng"), ("caps_lat", "caps_lng"), ("lat", "lon")):
        try:
            la = float(row[cla])
            out[cla] = _like(row[cla], la + sp["off_n"] / 111320)
            out[clo] = _like(row[clo], float(row[clo]) + sp["off_e"] / (111320 * math.cos(math.radians(la))))
        except (KeyError, ValueError):
            pass
    return out


async def new_record(rtype: str, data: dict) -> dict:
    seq = cap.seq
    destroyed = destroy_old_keys(seq // cap.epoch_size)
    if destroyed:
        await event(f"Chiave dell'epoca {destroyed[-1]} distrutta: le righe fino alla {seq - 1} non sono più riscrivibili", "key")
    return make_record(seq, rtype, data)


async def write_record(rec: dict):
    """Firma, cifra, salva nel log locale e invia: vale per dati, safe mode e ripresa."""
    seq = rec["seq"]
    env = build_envelope(cap.mission_id, rec, cap.keys[seq // cap.epoch_size], cap.cloud_pub)
    cap.prev_hash = record_hash(rec)
    cap.data_by_seq[seq] = rec["data"]
    cap.local_log.append(env)
    cap.persist()
    cap.last_box = env["box"]["ct"][:96]
    if cap.stolen and rec["type"] == "DATA":
        await attacker_forge(rec)
    if cap.online and await send_to_cloud(env, "live"):
        cap.sent.add(seq)
    cap.seq += 1
    if cap.online and cap.seq % cap.audit_every == 0:
        await run_audit()
    await push_state()


async def enter_safe_mode(w: dict, t: float, row: dict):
    lat = row.get("lat")
    info = {
        "motivo": "Spoofing lento: la posizione GNSS si sposta più di quanto spieghi la velocità",
        "rilevato_t": t, "inizio_stimato_t": w.get("inizio_t"),
        "spostamento_non_spiegato_m": w.get("accumulo_m"), "direzione": w.get("direzione"),
        "concordanza_pct": w.get("concordanza_pct"),
        "ultima_posizione_affidabile": ({"lat": w.get("pos_lat"), "lng": w.get("pos_lng")} if lat is not None else None),
        "azione": "drone fermo in posizione, in attesa dell'operatore",
    }
    rec = await new_record("SAFE_MODE", info)
    await write_record(rec)
    cap.safe = {**info, "riga": rec["seq"], "dal": time.strftime("%H:%M:%S")}
    cap.state = "safe mode"
    await event(f"SAFE MODE: spostamento non spiegato di {w.get('accumulo_m')} m verso {w.get('direzione')}, "
                f"iniziato a circa {w.get('inizio_t')} s. Scritto nella riga #{rec['seq']} della black box", "bad")
    await push_state()


def make_record(seq: int, rtype: str, data: dict) -> dict:
    return {
        "mission": cap.mission_id,
        "seq": seq,
        "epoch": seq // cap.epoch_size,
        "ts": now_iso(),
        "type": rtype,
        "data": data,
        "prev": cap.prev_hash,
    }


def destroy_old_keys(current_epoch: int) -> list[int]:
    destroyed = []
    for i in range(current_epoch):
        if cap.keys[i] is not None:
            cap.keys[i] = None   # in un sistema reale: azzeramento della memoria
            destroyed.append(i)
    return destroyed


async def attacker_forge(real_rec: dict):
    """Chi ha rubato le chiavi inietta una versione falsa della riga, firmata validamente."""
    e = real_rec["seq"] // cap.epoch_size
    key = cap.stolen.get(e)
    if key is None or not cap.online:
        return
    fake = copy.deepcopy(real_rec)
    for k, v in cap.forge_base.items():
        if k in fake["data"]:
            fake["data"][k] = v
    if fake["data"] == real_rec["data"]:
        nf = numeric_fields(fake["data"])
        if nf:
            fake["data"][nf[0]] = tamper_value(nf[0], fake["data"][nf[0]])
        else:
            fake["data"]["_nota"] = "valori normali"
    env = build_envelope(cap.mission_id, fake, key, cap.cloud_pub)
    await send_to_cloud(env, "live")


async def flight_loop():
    try:
        n = len(cap.rows)
        for i in range(n + 1):
            while cap.state == "in pausa":
                await asyncio.sleep(0.2)

            if i < n:
                t = row_time(cap.rows[i], i)
                seen = apply_spoof(cap.rows[i], t)
                cap.seen_rows.append(seen)
                w = cap.watch.update(seen, t)
                cap.watch_state = w
                rec = await new_record("DATA", seen)
                if w.get("attivo") and not w.get("taratura"):
                    # lo stato della sorveglianza viaggia firmato insieme al dato
                    rec["watch"] = {k: w[k] for k in ("accumulo_m", "livello", "concordanza_pct", "t")}
                alerts = await onboard_detector(i)
                if alerts:
                    rec["alerts"] = alerts     # fanno parte della riga: firmati e incatenati
                    cap.n_alerts += len(alerts)
                    for a in alerts:
                        await event(f"Rilevatore di bordo: {a['caso_label']} da {a['da_t']} s. "
                                    f"Allarme scritto nella riga #{rec['seq']} della black box", "bad")
                await write_record(rec)

                lvl = w.get("livello", "ok") if not w.get("taratura") else "ok"
                if lvl == "avviso" and cap.watch_level == "ok":
                    await event(f"Avviso: spostamento non spiegato di {w['accumulo_m']} m. Possibile spoofing lento", "warn")
                cap.watch_level = lvl
                if lvl == "safe" and not cap.safe:
                    await enter_safe_mode(w, t, seen)

                # safe mode: il drone resta fermo finché la centrale non interviene
                while cap.safe:
                    if cap.resume_req:
                        rec = await new_record("RESUME", {"esito": "controllo preso dalla centrale, segnale GNSS ripristinato",
                                                          "safe_mode_riga": cap.safe["riga"]})
                        await write_record(rec)
                        cap.safe, cap.spoof, cap.resume_req = None, None, False
                        cap.watch.reset()
                        cap.watch_state, cap.watch_level = {}, "ok"
                        cap.resume_rows.append(i + 1)
                        cap.state = "in volo"
                        await event("Centrale: controllo preso, volo ripreso dal punto in cui si era fermato", "ok")
                        await push_state()
                        break
                    await asyncio.sleep(0.3)
            else:
                rec = await new_record("END", {"righe_inviate": n, "chiusura": "fine missione"})
                await write_record(rec)
            await asyncio.sleep(1 / cap.speed)

        cap.state = "atterrata"
        destroy_old_keys(len(cap.keys))
        await event("Fine dei dati: missione chiusa, tutte le chiavi distrutte", "ok")
        await push_state()
        await finish_and_reconcile()
    except asyncio.CancelledError:
        pass


async def finish_and_reconcile():
    if not cap.online:
        await event("In attesa del segnale per la riconciliazione finale", "warn")
        while not cap.online:
            await asyncio.sleep(0.5)
    await flush_backlog()
    await event("Invio del log locale completo al cloud per il confronto", "info")
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(f"{CLOUD}/reconcile", json={"mission": cap.mission_id, "log": cap.local_log})
            cap.summary = r.json()
    except httpx.HTTPError as ex:
        await event(f"Riconciliazione fallita: {ex}", "bad")
        return
    cap.state = "conclusa"
    await event("Riconciliazione completata: vedi il riepilogo", "ok")
    await push_state()


# ---------------- API ----------------

@app.get("/")
async def index():
    return FileResponse(Path(__file__).parent / "static" / "capsule.html")


@app.websocket("/ws")
async def ws(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    await ws.send_json(cap.snapshot())
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        clients.discard(ws)


@app.post("/csv")
async def load_csv(body: dict):
    text = body.get("text", "")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = [dict(r) for r in csv.DictReader(io.StringIO(text), dialect=dialect)]
    rows = [{k.strip(): (v or "").strip() for k, v in r.items() if k} for r in rows]
    if not rows:
        return {"ok": False, "error": "Il CSV non contiene righe leggibili"}
    cap.rows = rows
    cap.csv_name = body.get("name", "volo.csv")
    await event(f"Caricato {cap.csv_name}: {len(rows)} righe, colonne: {', '.join(rows[0].keys())}")
    await push_state()
    return {"ok": True, "rows": len(rows)}


@app.post("/start")
async def start(body: dict):
    if not cap.rows:
        return {"ok": False, "error": "Carica prima il CSV del volo"}
    if cap.task and not cap.task.done():
        cap.task.cancel()
    rows, name = cap.rows, cap.csv_name
    cap.reset()
    cap.rows, cap.csv_name = rows, name
    cap.epoch_size = max(2, int(body.get("epoch_size", 10)))
    cap.speed = float(body.get("speed", 2))
    cap.audit_every = max(1, int(body.get("audit_every", 10)))

    try:
        async with httpx.AsyncClient(timeout=5) as c:
            cap.cloud_pub = bytes.fromhex((await c.get(f"{CLOUD}/pubkey")).json()["pub"])
    except httpx.HTTPError:
        return {"ok": False, "error": f"Cloud non raggiungibile su {CLOUD}: avvialo prima"}

    cap.mission_id = "M-" + time.strftime("%Y%m%d-%H%M%S")
    n_epochs = (len(cap.rows) + 1 + 40) // cap.epoch_size + 2   # margine per safe mode e riprese
    cap.keys = [new_signing_key() for _ in range(n_epochs)]
    genesis = secrets.token_hex(32)
    cap.prev_hash = genesis

    reg = {
        "mission": cap.mission_id,
        "epoch_size": cap.epoch_size,
        "genesis": genesis,
        "epoch_pubs": [raw_pub(k.public_key()).hex() for k in cap.keys],
        "rows_expected": len(cap.rows) + 1,
        "columns": list(cap.rows[0].keys()),
    }
    async with httpx.AsyncClient(timeout=5) as c:
        await c.post(f"{CLOUD}/mission", json=reg)

    cap.state = "in volo"
    await event(f"Missione {cap.mission_id} avviata: {n_epochs} chiavi generate in RAM, al cloud solo le pubbliche", "ok")
    cap.task = asyncio.create_task(flight_loop())
    await push_state()
    return {"ok": True}


@app.post("/pause")
async def pause():
    if cap.state == "in volo":
        cap.state = "in pausa"
    elif cap.state == "in pausa":
        cap.state = "in volo"
    await push_state()
    return {"ok": True}


@app.post("/speed")
async def speed(body: dict):
    cap.speed = max(0.2, min(30.0, float(body.get("speed", 2))))
    await push_state()
    return {"ok": True}


@app.post("/signal")
async def signal():
    cap.online = not cap.online
    if cap.online:
        await event("Segnale ripristinato", "ok")
        asyncio.create_task(flush_backlog())
    else:
        await event("Segnale perso: le righe restano cifrate solo nel log locale", "warn")
    await push_state()
    return {"ok": True}


@app.post("/attack/malware")
async def malware():
    """Malware con root: riscrive righe del log locale. Non può leggerle (sono cifrate
    verso il cloud), quindi le ricrea da zero con valori alterati e le firma con
    l'unica chiave che trova in RAM: quella dell'epoca corrente."""
    if cap.state not in ("in volo", "in pausa") or not cap.local_log:
        return {"ok": False, "error": "Il malware agisce solo durante il volo"}
    e = cap.seq // cap.epoch_size
    key = cap.keys[e] if e < len(cap.keys) else None
    if key is None:
        return {"ok": False, "error": "Nessuna chiave disponibile"}

    pending = [x for x in cap.local_log if x["seq"] not in cap.sent]
    sent_old = [x for x in cap.local_log if x["seq"] in cap.sent and x["seq"] // cap.epoch_size < e]
    targets = random.sample(pending, min(2, len(pending))) + random.sample(sent_old, min(2 if not pending else 1, len(sent_old)))
    if not targets:
        targets = [cap.local_log[-1]]

    touched = []
    for env in targets:
        s = env["seq"]
        src = cap.data_by_seq.get(s, {})
        fake_data = dict(src)
        for k in numeric_fields(fake_data)[:2]:
            fake_data[k] = tamper_value(k, fake_data[k])
        fake = {
            "mission": cap.mission_id, "seq": s, "epoch": s // cap.epoch_size,
            "ts": now_iso(), "type": "DATA", "data": fake_data,
            "prev": secrets.token_hex(32),  # non può conoscere l'hash vero: non legge le righe
        }
        new_env = build_envelope(cap.mission_id, fake, key, cap.cloud_pub)
        idx = cap.local_log.index(env)
        cap.local_log[idx] = new_env
        touched.append(s)
    cap.persist()
    cap.malware_done = True
    touched.sort()
    await event(f"MALWARE: riscritte nel log locale le righe {', '.join('#'+str(t) for t in touched)} "
                f"(firmate con la chiave dell'epoca {e})", "bad")
    await push_state()
    return {"ok": True, "rows": touched}


@app.post("/attack/keytheft")
async def keytheft():
    """Root durante il volo: copia dalla RAM la chiave corrente e quelle future,
    prova a riscrivere una riga del passato e poi inietta righe false."""
    if cap.state not in ("in volo", "in pausa"):
        return {"ok": False, "error": "Il furto avviene durante il volo"}
    e = cap.seq // cap.epoch_size
    cap.stolen = {i: k for i, k in enumerate(cap.keys) if i >= e and k is not None}
    last = cap.rows[min(cap.seq, len(cap.rows) - 1)]
    cap.forge_base = {k: last[k] for k in numeric_fields(last)}
    await event(f"FURTO CHIAVI: copiate {len(cap.stolen)} chiavi (dall'epoca {e} in poi). "
                f"Quelle delle epoche 0-{e - 1} non esistono più", "bad")

    # tentativo di riscrivere il passato con la chiave rubata
    old = [x for x in cap.local_log if x["seq"] // cap.epoch_size < e]
    if old and cap.online:
        target = random.choice(old)["seq"]
        src = dict(cap.data_by_seq.get(target, {}))
        for k in numeric_fields(src)[:1]:
            src[k] = cap.forge_base.get(k, src[k])
        rec = {"mission": cap.mission_id, "seq": target, "epoch": target // cap.epoch_size,
               "ts": now_iso(), "type": "DATA", "data": src, "prev": secrets.token_hex(32)}
        await send_to_cloud(build_envelope(cap.mission_id, rec, cap.stolen[e], cap.cloud_pub), "live")
        await event(f"L'attaccante prova a riscrivere la riga #{target} del passato con la chiave rubata", "bad")
    await push_state()
    return {"ok": True}


@app.post("/attack/spoof")
async def spoof(body: dict):
    if cap.state not in ("in volo", "in pausa"):
        return {"ok": False, "error": "Lo spoofing si avvia durante il volo"}
    rate = max(0.02, min(5.0, float(body.get("rate", 0.3))))
    cap.spoof = {"rate": rate, "ramp": 20.0, "ang": random.uniform(0, 360), "t0": None, "prev_t": None,
                 "off_e": 0.0, "off_n": 0.0}
    await event(f"SPOOFER ATTIVO (zona): sposta tutti i ricevitori, fino a {rate} m/s con partenza graduale", "bad")
    await push_state()
    return {"ok": True}


@app.post("/resume")
async def resume():
    """Comando dalla centrale: l'operatore prende il controllo e il volo riprende."""
    if not cap.safe:
        return {"ok": False, "error": "Nessuna safe mode in corso"}
    cap.resume_req = True
    return {"ok": True}


@app.post("/reset")
async def reset():
    if cap.task and not cap.task.done():
        cap.task.cancel()
    rows, name = cap.rows, cap.csv_name
    cap.reset()
    cap.rows, cap.csv_name = rows, name
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            await c.post(f"{CLOUD}/reset")
    except httpx.HTTPError:
        pass
    await event("Demo azzerata")
    await push_state()
    return {"ok": True}
