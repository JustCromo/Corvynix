"""Sorveglianza in tempo reale dello spoofing lento, riga per riga (gira sulla capsula).

Idea, in parole semplici:
  ogni campione la capsula PREVEDE dove dovrebbe essere il drone usando la velocità,
  e lo confronta con dove lo mette il GNSS. La differenza è la "sorpresa".
  - Con il GNSS sano le sorprese sono casuali: vanno di qua e di là e si annullano.
  - Con lo spoofing lento spingono sempre dalla stessa parte e si ACCUMULANO.
  Lo "spostamento non spiegato" è la somma delle sorprese, a cui a ogni passo si toglie
  una piccola tolleranza (così il rumore normale non si accumula mai).
    >= SOGLIA_AVVISO  -> avviso all'operatore
    >= SOGLIA_SAFE    -> safe mode

Nel sistema reale al posto della previsione semplificata si usano le innovazioni
dell'EKF dell'autopilota: il principio è identico.

Taratura automatica:
  - ritardo tra velocità e posizione (filtri, campionamento): quando il drone accelera o vira
    produce una sorpresa proporzionale alla variazione di velocità. Il sistema stima questo
    ritardo e lo compensa. Uno spoofing lento non è legato alle accelerazioni, quindi non
    viene "compensato" per errore;
  - tolleranza: almeno 5 cm/s, di più se i dati di quel drone sono più rumorosi.
"""
import math

SOGLIA_AVVISO = 2.5     # metri di spostamento non spiegato
SOGLIA_SAFE = 5.0       # metri
TOLLERANZA_MIN = 0.05   # m/s: deriva più lenta di così è considerata innocua (3 m al minuto)
CAMPIONI_TARATURA = 40


def _f(v):
    try:
        x = float(str(v).replace(",", "."))
        return x if math.isfinite(x) else None
    except (TypeError, ValueError):
        return None


def _col(row, *names):
    low = {k.lower(): k for k in row}
    for n in names:
        if n in low:
            return low[n]
    return None


class SpoofWatch:
    def __init__(self):
        self.reset()

    def reset(self):
        self.prev = None            # (t, e, n, ve, vn)
        self.R = [0.0, 0.0]         # spostamento non spiegato accumulato (est, nord)
        self.onset = None           # istante in cui l'accumulo è partito da zero
        self.onset_pos = None
        self.low_t = None           # ultimo istante in cui l'accumulo era trascurabile
        self.calib = []             # residui per la taratura
        self.bias = (0.0, 0.0)      # m/s di differenza costante misurata in taratura
        self.k = TOLLERANZA_MIN
        self.recent = []            # ultimi residui, per la "concordanza"
        self.level = "ok"
        self.lat0 = None
        self.cols = None
        self.tau = 0.0              # ritardo stimato tra velocità e posizione (s)
        self.s_rv = 0.0
        self.s_vv = 0.0

    # posizione in metri dal primo campione
    def _pos(self, row):
        c = self.cols
        if c["e"] and c["n"]:
            e, n = _f(row.get(c["e"])), _f(row.get(c["n"]))
            if e is not None and n is not None:
                return e, n
        if c["lat"] and c["lng"]:
            la, lo = _f(row.get(c["lat"])), _f(row.get(c["lng"]))
            if la is not None and lo is not None:
                if self.lat0 is None:
                    self.lat0, self.lng0 = la, lo
                return ((lo - self.lng0) * 111320 * math.cos(math.radians(self.lat0)),
                        (la - self.lat0) * 111320)
        return None

    def usable(self, row) -> bool:
        if self.cols is None:
            self.cols = {
                "t": _col(row, "t_s", "t", "tempo_s"), "dt": _col(row, "dt_s", "dt"),
                "e": _col(row, "est_m"), "n": _col(row, "nord_m"),
                "lat": _col(row, "lat"), "lng": _col(row, "lng", "lon"),
                "ve": _col(row, "vel_est_ms"), "vn": _col(row, "vel_nord_ms"),
            }
        c = self.cols
        return bool(c["ve"] and c["vn"] and ((c["e"] and c["n"]) or (c["lat"] and c["lng"])))

    def update(self, row: dict, t_fallback: float) -> dict:
        """Elabora un campione. Restituisce lo stato da mostrare e da firmare nella riga."""
        if not self.usable(row):
            return {"attivo": False}
        c = self.cols
        t = _f(row.get(c["t"])) if c["t"] else None
        t = t if t is not None else t_fallback
        p = self._pos(row)
        ve, vn = _f(row.get(c["ve"])), _f(row.get(c["vn"]))
        if p is None or ve is None or vn is None:
            return self.state(t)
        if self.prev is None or t <= self.prev[0]:
            self.prev = (t, p[0], p[1], ve, vn)
            return self.state(t)
        t0, e0, n0, ve0, vn0 = self.prev
        dt = t - t0
        # sorpresa: spostamento GNSS meno spostamento previsto dalla velocità
        re = (p[0] - e0) - (ve + ve0) / 2 * dt
        rn = (p[1] - n0) - (vn + vn0) / 2 * dt
        dve, dvn = ve - ve0, vn - vn0
        self.prev = (t, p[0], p[1], ve, vn)

        # stima del ritardo velocità/posizione (solo quando non c'è un accumulo sospetto)
        if math.hypot(*self.R) < SOGLIA_AVVISO / 2:
            self.s_rv += re * dve + rn * dvn
            self.s_vv += dve * dve + dvn * dvn
            if self.s_vv > 4.0:
                self.tau = max(-1.0, min(1.0, self.s_rv / self.s_vv))

        if len(self.calib) < CAMPIONI_TARATURA:
            self.calib.append((re, rn, dt, dve, dvn))
            if len(self.calib) == CAMPIONI_TARATURA:
                T = sum(x[2] for x in self.calib)
                cr = [(x[0] - self.tau * x[3], x[1] - self.tau * x[4], x[2]) for x in self.calib]
                # niente correzione di una "differenza costante": se c'è, deve emergere
                spread = (sum(math.hypot(x[0], x[1]) for x in cr) / CAMPIONI_TARATURA) / (T / CAMPIONI_TARATURA)
                self.k = max(TOLLERANZA_MIN, 0.08 * spread)
            return self.state(t)

        re -= self.bias[0] * dt + self.tau * dve
        rn -= self.bias[1] * dt + self.tau * dvn
        self.recent = (self.recent + [(re, rn)])[-40:]

        self.R = [self.R[0] + re, self.R[1] + rn]
        mag = math.hypot(*self.R)
        shrink = self.k * dt
        if mag <= shrink:
            self.R = [0.0, 0.0]
        else:
            self.R = [x * (mag - shrink) / mag for x in self.R]
        # inizio stimato dell'attacco: l'ultimo momento in cui l'accumulo era trascurabile
        if math.hypot(*self.R) < 0.2 * SOGLIA_AVVISO:
            self.low_t = t
            self.onset_pos = (row.get(c["lat"]), row.get(c["lng"])) if c["lat"] else None
        self.onset = self.low_t
        return self.state(t)

    def state(self, t) -> dict:
        mag = math.hypot(*self.R)
        level = "safe" if mag >= SOGLIA_SAFE else ("avviso" if mag >= SOGLIA_AVVISO else "ok")
        self.level = level
        # concordanza: quante sorprese recenti spingono nella stessa direzione dell'accumulo
        conc = None
        if self.recent and mag > 0:
            ux, uy = self.R[0] / mag, self.R[1] / mag
            conc = round(100 * sum(1 for a, b in self.recent if a * ux + b * uy > 0) / len(self.recent))
        direction = None
        if mag > 0:
            ang = (math.degrees(math.atan2(self.R[0], self.R[1])) + 360) % 360
            direction = ["nord", "nord-est", "est", "sud-est", "sud", "sud-ovest", "ovest", "nord-ovest"][int((ang + 22.5) // 45) % 8]
        return {
            "attivo": True, "taratura": len(self.calib) < CAMPIONI_TARATURA,
            "accumulo_m": round(mag, 2), "soglia_avviso_m": SOGLIA_AVVISO, "soglia_safe_m": SOGLIA_SAFE,
            "tolleranza_ms": round(self.k, 3), "ritardo_s": round(self.tau, 3), "concordanza_pct": conc, "direzione": direction,
            "inizio_t": self.onset, "livello": level, "t": t,
            "pos_lat": self.onset_pos[0] if self.onset_pos else None,
            "pos_lng": self.onset_pos[1] if self.onset_pos else None,
        }
