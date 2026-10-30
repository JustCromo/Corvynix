"""Primitive crittografiche condivise tra capsula e cloud.

- Integrità:      SHA-256 + catena (ogni riga contiene l'hash della precedente)
- Autenticità:    firma Ed25519 con chiavi "usa e getta" per epoca
- Riservatezza:   cifratura ibrida X25519 + HKDF + AES-GCM verso la chiave
                  pubblica del cloud (la capsula NON può decifrare: la chiave
                  effimera viene buttata subito dopo l'uso)
"""
import base64
import hashlib
import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def canon(obj) -> bytes:
    """JSON canonico: stesso oggetto -> stessi byte -> stesso hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def record_hash(rec: dict) -> str:
    return sha256_hex(canon(rec))


def raw_pub(pubkey) -> bytes:
    return pubkey.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# ---------- firma ----------

def new_signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def sign(key: Ed25519PrivateKey, digest_hex: str) -> str:
    return b64e(key.sign(digest_hex.encode()))


def verify(pub_raw: bytes, sig_b64: str, digest_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(b64d(sig_b64), digest_hex.encode())
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------- cifratura ----------

def _derive(shared: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"blackbox-demo-v1").derive(shared)


def aad_for(mission_id: str, seq: int) -> bytes:
    # lega il ciphertext alla missione e alla posizione: non si può spostare
    return f"{mission_id}:{seq}".encode()


def seal(cloud_pub_raw: bytes, plaintext: bytes, aad: bytes) -> dict:
    eph = X25519PrivateKey.generate()  # usata una volta e poi persa
    shared = eph.exchange(X25519PublicKey.from_public_bytes(cloud_pub_raw))
    nonce = os.urandom(12)
    ct = AESGCM(_derive(shared)).encrypt(nonce, plaintext, aad)
    return {"eph": b64e(raw_pub(eph.public_key())), "nonce": b64e(nonce), "ct": b64e(ct)}


def unseal(cloud_priv: X25519PrivateKey, box: dict, aad: bytes) -> bytes:
    shared = cloud_priv.exchange(X25519PublicKey.from_public_bytes(b64d(box["eph"])))
    return AESGCM(_derive(shared)).decrypt(b64d(box["nonce"]), b64d(box["ct"]), aad)


def build_envelope(mission_id: str, rec: dict, key: Ed25519PrivateKey, cloud_pub_raw: bytes) -> dict:
    """Riga -> hash -> firma -> cifratura. Restituisce ciò che esce dalla capsula."""
    h = record_hash(rec)
    payload = {"rec": rec, "hash": h, "sig": sign(key, h)}
    box = seal(cloud_pub_raw, canon(payload), aad_for(mission_id, rec["seq"]))
    return {"mission": mission_id, "seq": rec["seq"], "box": box}


NUMERIC_SKIP = ("time", "date", "timestamp", "stamp", "seq", "volo", "anomalia", "waypoint",
                "fix", "modalita", "satelliti", "id")
TIME_EXACT = ("t_s", "dt_s", "t", "ts", "tempo", "tempo_s")


def numeric_fields(row: dict) -> list:
    """Campi numerici "di misura" (esclude tempo, identificativi, etichette, contatori)."""
    out = []
    for k, v in row.items():
        kl = k.lower()
        if kl in TIME_EXACT or any(s in kl for s in NUMERIC_SKIP):
            continue
        try:
            float(str(v).replace(",", "."))
            out.append(k)
        except ValueError:
            pass
    # i campi più "interessanti" per un attaccante (posizione, quota, temperatura) per primi
    pri = ("lat", "lng", "lon", "quota", "alt", "temp")
    return sorted(out, key=lambda k: 0 if any(p in k.lower() for p in pri) else 1)


def tamper_value(field: str, value: str) -> str:
    """Alterazione credibile: sposta la posizione di ~150 m, il resto del 10%."""
    v = float(str(value).replace(",", "."))
    f = field.lower()
    if any(p in f for p in ("lat", "lng", "lon")):
        return f"{v + 0.0014:.7f}"
    return f"{round(v * 1.1 + (0.5 if v == 0 else 0), 4)}"
