"""Rilevatore di anomalie GNSS su telemetria di volo (punto 2).

Lavora su qualsiasi CSV con le colonne della telemetria (nomi riconosciuti per prefisso).
Ogni controllo confronta il GNSS con qualcosa di indipendente da lui:

  salto_posizione   spostamento GNSS incoerente con velocità x tempo (cinematica)
  ritorno_inizio    salto che riporta la posizione al punto di decollo (replay)
  deriva_lenta      il GNSS del drone si allontana gradualmente da quello della capsula
                    o dalla posizione stimata integrando la velocità
  capsula_bloccata  la posizione della capsula resta ferma mentre il drone vola
  spoofing_di_zona  drone e capsula "si spostano insieme" in modo fisicamente impossibile:
                    salto simultaneo, quota GNSS contro barometro, accelerazioni
  qualita_gnss      pochi satelliti, fix degradato, incertezza alta (degrado o jamming)

Le soglie sono adattive: ogni file fa da riferimento a se stesso (mediana + MAD),
con un minimo fisico sotto il quale non si scende.

Spoofing graduale ("intelligente"): lo spoofer sposta la posizione così poco a ogni
campione da restare sotto qualsiasi soglia istantanea. Per questo alcuni scarti
vengono anche ACCUMULATI nel tempo con il CUSUM (somma cumulativa, Page 1954):
il rumore casuale si annulla, una spinta piccola ma sempre nella stessa direzione
cresce fino a superare la soglia. Scarti accumulati:
  - distanza drone-capsula            (un solo ricevitore ingannato)
  - prua (bussola) contro direzione GNSS
    se lo spoofer trascina il GNSS, l'autopilota "corregge" e il drone vero vola
    leggermente di traverso: compare un angolo piccolo e costante.
    ATTENZIONE: un cambio di vento produce la stessa firma. Da solo è un indizio
    debole ("deriva_sospetta"), da confermare con una fonte indipendente
    (vento misurato, GPS interno, Galileo OSNMA, velocità integrata dall'IMU).
  - quota GNSS contro barometro        (deriva verticale)
"""
import math
import re
import statistics

CASES = {
    "salto_posizione": "Salto di posizione",
    "ritorno_inizio": "Ritorno al punto di partenza",
    "deriva_lenta": "Deriva lenta",
    "capsula_bloccata": "GNSS della capsula bloccato",
    "spoofing_di_zona": "Spoofing di zona",
    "qualita_gnss": "Qualità GNSS degradata",
    "deriva_sospetta": "Possibile deriva graduale (da confermare)",
}
WEAK = {"deriva_sospetta"}   # indizi che da soli non bastano ad accusare uno spoofing
PRIORITY = ["capsula_bloccata", "ritorno_inizio", "spoofing_di_zona", "salto_posizione",
            "deriva_lenta", "qualita_gnss", "deriva_sospetta"]
NEG_LABELS = {"", "0", "0.0", "false", "no", "nessuna", "none", "normale", "ok", "nan"}


# ---------------- utilità ----------------

def fnum(v):
    try:
        x = float(str(v).replace(",", "."))
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def find_col(cols, *prefixes, exact=None):
    low = {c.lower(): c for c in cols}
    if exact:
        for e in exact:
            if e in low:
                return low[e]
    for p in prefixes:
        for c in cols:
            if c.lower().startswith(p):
                return c
    return None


def robust_thr(values, floor, k):
    vals = [v for v in values if v is not None]
    if len(vals) < 5:
        return floor
    med = statistics.median(vals)
    mad = statistics.median(abs(v - med) for v in vals)
    return max(floor, med + k * 1.4826 * mad)


def cusum(series, k=0.75, h=18.0, sigma_floor=0.1, one_sided=False):
    """CUSUM a due lati su uno scarto. La linea di base (media e dispersione) si stima
    sulla prima parte valida del volo. Restituisce i tratti in allarme:
    (inizio stimato, fine, direzione, picco). L'inizio è l'istante in cui la somma
    ha cominciato a crescere: è la stima di quando è iniziata la deriva."""
    idx = [i for i, x in enumerate(series) if x is not None]
    if len(idx) < 40:
        return [], None
    base = [series[i] for i in idx[: max(30, len(idx) // 5)]]
    mu = statistics.median(base)
    sigma = max(sigma_floor, 1.4826 * statistics.median(abs(x - mu) for x in base))
    out = []
    for sign in ((1,) if one_sided else (1, -1)):
        S, start, alarm = 0.0, None, None
        for i in idx:
            z = sign * (series[i] - mu) / sigma
            if S == 0.0:
                start = i
            S = min(1.5 * h, max(0.0, S + z - k))   # tetto: la somma si scarica presto a deriva finita
            if S > h and alarm is None:
                alarm = [start, i, sign, S, i]
            if alarm is not None:
                alarm[3] = max(alarm[3], S)
                if z > max(k, 2.0):
                    alarm[1] = i                   # ultimo campione che spinge ancora chiaramente
                if S < h / 2:
                    out.append(tuple(alarm[:4]))
                    alarm = None
        if alarm is not None:
            out.append(tuple(alarm[:4]))
    return out, (mu, sigma)


def baro_alt(p_hpa, p0=1013.25):
    return 44330.0 * (1 - (p_hpa / p0) ** 0.1903)


# ---------------- analisi ----------------

def analyze(rows: list[dict]) -> dict:
    if not rows:
        return {"ok": False, "error": "Il file non contiene righe"}
    cols = list(rows[0].keys())
    C = {
        "t": find_col(cols, exact=("t_s", "t", "tempo_s", "time_s")),
        "dt": find_col(cols, exact=("dt_s", "dt")),
        "mode": find_col(cols, "modalita", "mode", "fase"),
        "lat": find_col(cols, exact=("lat", "latitudine")),
        "lng": find_col(cols, exact=("lng", "lon", "longitudine")),
        "e": find_col(cols, exact=("est_m",)), "n": find_col(cols, exact=("nord_m",)),
        "q_amsl": find_col(cols, "quota_amsl"), "q_rel": find_col(cols, "quota_rel"),
        "p": find_col(cols, "pressione"),
        "fix": find_col(cols, "fix"), "sat": find_col(cols, exact=("satelliti",)),
        "unc": find_col(cols, "incertezza_pos"),
        "vn": find_col(cols, "vel_nord"), "ve": find_col(cols, "vel_est"),
        "spd": find_col(cols, exact=("velocita_ms", "velocita")),
        "hdg": find_col(cols, "heading", "prua", "yaw"),
        "ax": find_col(cols, exact=("acc_x",)), "ay": find_col(cols, exact=("acc_y",)),
        "clat": find_col(cols, exact=("caps_lat",)), "clng": find_col(cols, exact=("caps_lng", "caps_lon")),
        "ce": find_col(cols, exact=("caps_est_m",)), "cn": find_col(cols, exact=("caps_nord_m",)),
        "csat": find_col(cols, exact=("caps_satelliti",)),
        "dist": find_col(cols, "distanza"),
        "label": find_col(cols, exact=("anomalia", "label", "etichetta")),
    }
    g = lambda i, k: fnum(rows[i].get(C[k])) if C[k] else None
    n = len(rows)

    # tempo
    t = [g(i, "t") for i in range(n)]
    if any(x is None for x in t):
        acc, t = 0.0, []
        for i in range(n):
            d = g(i, "dt") or 1.0
            t.append(acc)
            acc += d
    dt = [None] + [max(1e-3, t[i] - t[i - 1]) for i in range(1, n)]

    # posizioni in metri (est, nord)
    lat0 = g(0, "lat") or g(0, "clat") or 0.0
    kx = 111320.0 * math.cos(math.radians(lat0))

    def pos(i, e, nn, la, lo):
        if C[e] and C[nn] and g(i, e) is not None and g(i, nn) is not None:
            return (g(i, e), g(i, nn))
        if C[la] and C[lo] and g(i, la) is not None and g(i, lo) is not None:
            return ((g(i, lo) - (g(0, lo) or 0)) * kx, (g(i, la) - lat0) * 111320.0)
        return None

    P = [pos(i, "e", "n", "lat", "lng") for i in range(n)]
    Pc = [pos(i, "ce", "cn", "clat", "clng") for i in range(n)]
    V = [(g(i, "ve"), g(i, "vn")) if C["ve"] and C["vn"] else None for i in range(n)]
    V = [v if v and None not in v else None for v in V]
    spd = [g(i, "spd") if C["spd"] else (math.hypot(*V[i]) if V[i] else None) for i in range(n)]
    modes = [str(rows[i].get(C["mode"], "")).strip().lower() if C["mode"] else "" for i in range(n)]

    def dist_of(i):
        d = g(i, "dist")
        if d is not None:
            return d
        if P[i] and Pc[i]:
            return math.hypot(P[i][0] - Pc[i][0], P[i][1] - Pc[i][1])
        return None

    dist = [dist_of(i) for i in range(n)]
    moving_modes = lambda m: not any(x in m for x in ("decoll", "atterr", "takeoff", "land", "terra", "ground"))

    # --- segnali grezzi ---
    def kin_res(PP, i):
        if i == 0 or not PP[i] or not PP[i - 1] or not V[i] or not V[i - 1]:
            return None
        vx = (V[i][0] + V[i - 1][0]) / 2 * dt[i]
        vy = (V[i][1] + V[i - 1][1]) / 2 * dt[i]
        return math.hypot(PP[i][0] - PP[i - 1][0] - vx, PP[i][1] - PP[i - 1][1] - vy)

    kd = [kin_res(P, i) for i in range(n)]
    kc = [kin_res(Pc, i) for i in range(n)]

    T0_kd = robust_thr(kd, 6.0, 10)
    # deriva rispetto alla posizione stimata integrando la velocità (finestra ~10 s)
    dr = [None] * n
    for i in range(1, n):
        j = i
        while j > 0 and t[i] - t[j - 1] <= 10.0:
            j -= 1
        if j == i or not P[i] or not P[j]:
            continue
        if any(kd[k] is not None and kd[k] > T0_kd for k in range(j + 1, i + 1)):
            continue   # nella finestra c'è un salto: è già spiegato dal controllo cinematico
        sx = sy = 0.0
        ok = True
        for k in range(j + 1, i + 1):
            if not V[k] or not V[k - 1]:
                ok = False
                break
            sx += (V[k][0] + V[k - 1][0]) / 2 * dt[k]
            sy += (V[k][1] + V[k - 1][1]) / 2 * dt[k]
        if ok:
            dr[i] = math.hypot(P[i][0] - P[j][0] - sx, P[i][1] - P[j][1] - sy)

    # quota GNSS contro barometro (relativa all'inizio)
    baro = [None] * n
    baro_signed = [None] * n
    if C["p"] and (C["q_amsl"] or C["q_rel"]):
        qk = "q_amsl" if C["q_amsl"] else "q_rel"
        i0 = next((i for i in range(n) if g(i, "p") and g(i, qk) is not None), None)
        if i0 is not None:
            hb0, q0 = baro_alt(g(i0, "p")), g(i0, qk)
            raw = [((g(i, qk) - q0) - (baro_alt(g(i, "p")) - hb0)) if g(i, "p") and g(i, qk) is not None else None
                   for i in range(n)]
            med = statistics.median([x for x in raw if x is not None] or [0])
            baro = [abs(x - med) if x is not None else None for x in raw]
            baro_signed = raw

    # accelerazione dal GNSS contro accelerometri
    accm = [None] * n
    for i in range(1, n):
        if V[i] and V[i - 1] and C["ax"] and C["ay"] and g(i, "ax") is not None and g(i, "ay") is not None:
            ag = math.hypot(V[i][0] - V[i - 1][0], V[i][1] - V[i - 1][1]) / dt[i]
            accm[i] = max(0.0, ag - math.hypot(g(i, "ax"), g(i, "ay")))

    # --- soglie adattive ---
    T = {
        "kd": robust_thr(kd, 6.0, 10), "kc": robust_thr(kc, 6.0, 10),
        "dist": robust_thr(dist, 5.0, 8), "dr": robust_thr(dr, 8.0, 10),
        "baro": robust_thr(baro, 8.0, 10), "acc": robust_thr(accm, 6.0, 12),
    }
    unc_vals = [g(i, "unc") for i in range(n)]
    unc_med = statistics.median([u for u in unc_vals if u is not None] or [0])
    T["unc"] = max(3000.0, 3 * unc_med)
    start = next((p for p in P if p), None)
    far_from_start = 0.0

    # --- scarti piccoli ma persistenti: CUSUM ---
    unc_all = [g(i, "unc") for i in range(n)]
    unc_m0 = statistics.median([u for u in unc_all if u is not None] or [0])

    def degraded(i):
        return ((g(i, "sat") is not None and g(i, "sat") < 6) or (g(i, "fix") is not None and g(i, "fix") < 3)
                or (g(i, "unc") is not None and g(i, "unc") > max(3000.0, 2 * unc_m0)))
    # un ricevitore che dichiara di essere incerto non entra nell'accumulo
    clean = lambda ser: [None if x is None or degraded(i) else x for i, x in enumerate(ser)]
    crab = [None] * n
    if C["hdg"]:
        for i in range(n):
            h_ = g(i, "hdg")
            if h_ is None or not V[i] or spd[i] is None or spd[i] < 3 or not moving_modes(modes[i]):
                continue
            course = math.degrees(math.atan2(V[i][0], V[i][1]))
            crab[i] = (h_ - course + 180) % 360 - 180
    slow = []   # (inizio, fine, caso, motivo)
    for series, kw, case_if_alone, text in (
        (clean(dist), dict(one_sided=True, sigma_floor=0.3), "deriva_lenta",
         "distanza drone-capsula in crescita piccola ma costante"),
        (clean(crab), dict(sigma_floor=0.5), "deriva_sospetta",
         "prua e direzione GNSS divergono di un angolo piccolo e costante (compatibile anche con un cambio di vento)"),
        (clean(baro_signed), dict(sigma_floor=0.5), "spoofing_di_zona",
         "quota GNSS e barometro si separano lentamente"),
    ):
        segs_c, base = cusum(series, **kw)
        for a, b, sign, peak in segs_c:
            mu, sg = base
            shift = statistics.median([series[j] for j in range(a, b + 1) if series[j] is not None]) - mu
            unit = "°" if "prua" in text else " m"
            slow.append((a, b, case_if_alone,
                         f"{text}: scostamento medio {shift:+.1f}{unit}, persistente per {t[b] - t[a]:.0f} s"))
    slow_at = {}
    for a, b, case, why in slow:
        for j in range(a, b + 1):
            slow_at.setdefault(j, []).append((case, why))

    # --- valutazione riga per riga ---
    flags = []
    frozen_run = 0
    for i in range(n):
        why, lab = [], set()
        if P[i] and start:
            dstart = math.hypot(P[i][0] - start[0], P[i][1] - start[1])
        else:
            dstart = None

        # un GNSS che dichiara incertezza alta non sta mentendo: le tolleranze crescono con essa
        unc_m = (g(i, "unc") or 0) / 1000.0
        tol = 4 * unc_m
        jd = kd[i] is not None and kd[i] > max(T["kd"], tol)
        jc = kc[i] is not None and kc[i] > max(T["kc"], tol)
        dh = dist[i] is not None and dist[i] > max(T["dist"], tol)
        drh = dr[i] is not None and dr[i] > max(T["dr"], 2 * tol)

        # capsula bloccata
        if i > 0 and Pc[i] and Pc[i - 1] and spd[i] is not None and spd[i] > 1.0 and \
                math.hypot(Pc[i][0] - Pc[i - 1][0], Pc[i][1] - Pc[i - 1][1]) < 0.02:
            frozen_run += 1
        else:
            frozen_run = 0
        if frozen_run >= 4:
            lab.add("capsula_bloccata")
            why.append(f"posizione capsula ferma da {frozen_run} campioni con drone a {spd[i]:.1f} m/s")
            if frozen_run == 4:   # marca anche i campioni iniziali del blocco
                for k in range(1, 4):
                    if i - k >= 0:
                        flags[i - k]["labels"].add("capsula_bloccata")

        if jd and jc and not dh:
            lab.add("spoofing_di_zona")
            why.append(f"drone e capsula saltano insieme ({kd[i]:.0f} m e {kc[i]:.0f} m oltre la cinematica)")
        elif jd:
            if dstart is not None and dstart < max(25.0, T["dist"]) and far_from_start > 100 and moving_modes(modes[i]):
                lab.add("ritorno_inizio")
                why.append(f"la posizione torna a {dstart:.0f} m dal decollo (prima era a {far_from_start:.0f} m)")
            else:
                lab.add("salto_posizione")
                why.append(f"spostamento incoerente con la velocità: scarto {kd[i]:.0f} m")
        if dh:
            why.append(f"distanza drone-capsula {dist[i]:.1f} m (soglia {T['dist']:.1f})")
        if drh:
            why.append(f"posizione diversa da quella stimata con la velocità di {dr[i]:.0f} m in 10 s")
            if not dh and (Pc[i] or C["dist"]):
                lab.add("spoofing_di_zona")   # drone e capsula concordi, ma contro la fisica
        if baro[i] is not None and baro[i] > T["baro"]:
            why.append(f"quota GNSS e barometro divergono di {baro[i]:.0f} m")
            if not dh:
                lab.add("spoofing_di_zona")
        if accm[i] is not None and accm[i] > T["acc"] and (lab or dh or drh):
            # solo come prova a supporto: da sola è troppo sensibile al riferimento degli accelerometri
            why.append(f"variazione di velocità GNSS non vista dagli accelerometri ({accm[i]:.1f} m/s²)")
        q = []
        if g(i, "sat") is not None and g(i, "sat") < 6:
            q.append(f"{g(i, 'sat'):.0f} satelliti")
        if g(i, "fix") is not None and g(i, "fix") < 3:
            q.append(f"fix {g(i, 'fix'):.0f}")
        if g(i, "unc") is not None and g(i, "unc") > T["unc"]:
            q.append(f"incertezza {g(i, 'unc') / 1000:.1f} m")
        if q:
            lab.add("qualita_gnss")
            why.append("qualità GNSS bassa: " + ", ".join(q))
        if (dh or drh) and not lab - {"qualita_gnss"}:
            lab.add("deriva_lenta")
        for case, w in slow_at.get(i, []):
            if case in ("spoofing_di_zona", "deriva_sospetta") and dh:
                case = "deriva_lenta"      # il drone si separa dalla capsula: è il suo ricevitore a mentire
            if not lab - {"qualita_gnss"}:
                lab.add(case)
            why.append(w)

        if dstart is not None and not lab:
            far_from_start = max(far_from_start, dstart)
        flags.append({"i": i, "t": t[i], "labels": lab, "why": why})

    # --- segmenti: righe anomale consecutive (tollerati buchi di 2 righe) ---
    segs, cur = [], None
    for f in flags:
        if f["labels"]:
            if cur and f["i"] - cur["end"] <= 3:
                cur["end"] = f["i"]
                cur["rows"].append(f["i"])
            else:
                cur = {"start": f["i"], "end": f["i"], "rows": [f["i"]]}
                segs.append(cur)
    out_segs = []
    for s in segs:
        labs = set().union(*(flags[i]["labels"] for i in s["rows"]))
        onset = set().union(*(flags[i]["labels"] for i in s["rows"][:3]))   # il caso lo decide l'innesco
        case = next(c for c in PRIORITY if c in onset)
        # la somma cumulativa anticipa l'inizio di qualche istante: se subito dopo compare
        # una causa precisa (salto, ritorno, capsula ferma), la diagnosi è quella
        if case in ("deriva_lenta", "spoofing_di_zona"):
            early = set().union(*(flags[i]["labels"] for i in s["rows"] if t[i] - t[s["start"]] <= 10.0))
            sharp = [c for c in ("capsula_bloccata", "ritorno_inizio", "salto_posizione") if c in early]
            if sharp:
                case = sharp[0]
        if case in ("deriva_lenta", "qualita_gnss") and len(s["rows"]) < 3:
            continue   # evidenza troppo breve per questi casi
        # una voce per tipo di prova, con il valore di picco
        best = {}
        for i in s["rows"]:
            for w in flags[i]["why"]:
                key = re.sub(r"\d+(\.\d+)?", "#", w)
                nums = [float(x) for x in re.findall(r"\d+(?:\.\d+)?", w)] or [0]
                if key not in best or nums[0] > best[key][0]:
                    best[key] = (nums[0], w, len(best) if key not in best else best[key][2])
        reasons = [w for _, w, _ in sorted(best.values(), key=lambda x: x[2])]
        out_segs.append({
            "case": case, "case_label": CASES[case],
            "from_row": s["start"], "to_row": s["end"],
            "from_t": round(t[s["start"]], 2), "to_t": round(t[s["end"]], 2),
            "rows": s["end"] - s["start"] + 1, "also": sorted(labs - {case}),
            "reasons": reasons[:5],
        })
    flagged = set()
    for s in out_segs:
        flagged.update(range(s["from_row"], s["to_row"] + 1))

    # --- punteggio ---
    weight = {"spoofing_di_zona": 3, "ritorno_inizio": 3, "salto_posizione": 2.5, "deriva_lenta": 2.5,
              "capsula_bloccata": 2, "qualita_gnss": 1, "deriva_sospetta": 0.4}
    score = sum(weight[s["case"]] * (1 + math.log10(s["rows"])) for s in out_segs)
    score = round(min(100.0, score * 6), 1)
    strong = [sg for sg in out_segs if sg["case"] not in WEAK]
    if not out_segs:
        verdict = "Nessuna anomalia rilevata"
    elif not strong:
        verdict = (f"Nessuno spoofing accertato; indizio debole da confermare tra "
                   f"{out_segs[0]['from_t']} s e {out_segs[0]['to_t']} s")
    else:
        main = max(strong, key=lambda s: weight[s["case"]] * s["rows"])
        verdict = f"{main['case_label']} tra {main['from_t']} s e {main['to_t']} s"

    # --- confronto con l'etichetta del dataset, se presente ---
    ev = None
    if C["label"]:
        truth = [str(r.get(C["label"], "")).strip().lower() not in NEG_LABELS for r in rows]
        tp = sum(1 for i in range(n) if truth[i] and i in flagged)
        fp = sum(1 for i in range(n) if not truth[i] and i in flagged)
        fn = sum(1 for i in range(n) if truth[i] and i not in flagged)
        events, cur = [], None
        for i in range(n):
            if truth[i]:
                if cur and i == cur[1] + 1:
                    cur[1] = i
                else:
                    cur = [i, i]
                    events.append(cur)
        ev_res = []
        for a, b in events:
            hit = [i for i in range(a, b + 1) if i in flagged]
            ev_res.append({"from_t": round(t[a], 2), "to_t": round(t[b], 2), "rilevato": bool(hit),
                           "ritardo_s": round(t[hit[0]] - t[a], 2) if hit else None})
        false_segs = [s for s in out_segs if not any(truth[i] for i in range(s["from_row"], s["to_row"] + 1))]
        ev = {
            "colonna": C["label"],
            "righe_anomale_vere": sum(truth), "righe_segnalate": len(flagged),
            "precisione": round(tp / (tp + fp), 3) if tp + fp else None,
            "copertura": round(tp / (tp + fn), 3) if tp + fn else None,
            "eventi": ev_res, "eventi_rilevati": sum(e["rilevato"] for e in ev_res),
            "falsi_allarmi": len(false_segs),
        }

    used = {k: v for k, v in C.items() if v}
    missing = [k for k in ("vn", "ve", "p", "clat", "dist", "ax") if not C[k]]
    return {
        "ok": True, "rows": n, "duration_s": round(t[-1] - t[0], 2) if n > 1 else 0,
        "score": score, "verdict": verdict, "segments": out_segs, "weak_only": bool(out_segs) and not strong,
        "thresholds": {k: round(v, 2) for k, v in T.items()},
        "columns_used": used, "missing": missing, "evaluation": ev,
        "timeline": [{"t": round(t[i], 2), "dist": round(dist[i], 2) if dist[i] is not None else None,
                      "flag": i in flagged} for i in range(0, n, max(1, n // 600))],
    }
