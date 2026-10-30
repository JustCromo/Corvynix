"""Valuta il rilevatore su tutti i CSV di una cartella (i dati non escono dal PC).

Uso:  .venv/bin/python valuta.py /percorso/cartella_csv
"""
import csv
import io
import sys
from pathlib import Path

from detector import analyze


def load(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    return [{k.strip(): (v or "").strip() for k, v in r.items() if k}
            for r in csv.DictReader(io.StringIO(text), dialect=dialect)]


def main():
    folder = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    files = sorted(folder.glob("*.csv"))
    if not files:
        print(f"Nessun CSV in {folder}")
        return
    for f in files:
        r = analyze(load(f))
        print(f"\n=== {f.name}  ({r.get('rows', 0)} righe, {r.get('duration_s', 0)} s)")
        if not r.get("ok"):
            print("   ", r.get("error"))
            continue
        print(f"    esito: {r['verdict']}  ·  punteggio {r['score']}")
        for s in r["segments"]:
            print(f"    - {s['case_label']}: {s['from_t']}-{s['to_t']} s ({s['rows']} righe)")
            for w in s["reasons"][:2]:
                print(f"        {w}")
        e = r["evaluation"]
        if e:
            rit = [x["ritardo_s"] for x in e["eventi"] if x["ritardo_s"] is not None]
            print(f"    confronto con «{e['colonna']}»: eventi {e['eventi_rilevati']}/{len(e['eventi'])}, "
                  f"precisione {e['precisione']}, copertura {e['copertura']}, falsi allarmi {e['falsi_allarmi']}"
                  + (f", ritardo medio {sum(rit) / len(rit):.1f} s" if rit else ""))
        if r["missing"]:
            print(f"    colonne non trovate: {', '.join(r['missing'])}")
        print(f"    soglie usate: {r['thresholds']}")


if __name__ == "__main__":
    main()
