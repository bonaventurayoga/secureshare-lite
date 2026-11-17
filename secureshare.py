"""
SecureShare-Lite: berbagi file terenkripsi + bertanda tangan lewat server TIDAK tepercaya (Checkpoint 3).

Alur: Alice (pengirim) -> Server (penyimpan, tidak dipercaya) -> Bob (penerima)

  - PKI            : CA menerbitkan sertifikat berisi 2 kunci publik: Ed25519 (tanda tangan) + X25519 (enkripsi)
  - Isi file       : AES-256-GCM dengan kunci file acak (file key) per file/versi
  - Kunci file     : dibungkus ke kunci X25519 Bob (ECIES-style: ephemeral DH + HKDF + AES-GCM)
  - Autentikasi    : Ed25519 menandatangani amplop (header, kunci terbungkus, hash ciphertext)
  - Anti-rollback  : nomor versi di header yang ditandatangani; penerima menyimpan versi terakhir
                     PER (pengirim, file_id), dan memeriksa bahwa file_id sama dengan yang diminta
  - Bukti publik   : verify_envelope(..., at_time=...) memeriksa sertifikat pada waktu bukti ditandatangani

Ini bahan belajar, BUKAN pengganti PGP/age/S-MIME.
"""
import os
import json
import time
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def raw(pub) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# --------------------------------------------------------------------------
# 1. PKI: sertifikat = (nama, kunci tanda tangan, kunci enkripsi, masa berlaku) ditandatangani CA
# --------------------------------------------------------------------------
def _cert_body(name: str, sign_pub: bytes, enc_pub: bytes, exp: int) -> bytes:
    return b"SSL-CERT|" + name.encode() + b"|" + sign_pub + enc_pub + b"|" + str(exp).encode()


class CA:
    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()
        self.public = self._sk.public_key()          # di-pin di aplikasi (out-of-band)

    def issue(self, name: str, sign_pub: bytes, enc_pub: bytes, ttl: int = 86400 * 30) -> dict:
        assert "|" not in name
        exp = int(time.time()) + ttl
        sig = self._sk.sign(_cert_body(name, sign_pub, enc_pub, exp))
        return {"name": name, "sign_pub": sign_pub.hex(), "enc_pub": enc_pub.hex(),
                "exp": exp, "sig": sig.hex()}


def verify_cert(ca_pub: Ed25519PublicKey, cert: dict, at_time: float = None):
    """Kembalikan (nama, Ed25519 pub, X25519 pub) jika sertifikat sah; selain itu exception.
    at_time: waktu acuan pemeriksaan masa berlaku (default: sekarang)."""
    sp, ep = bytes.fromhex(cert["sign_pub"]), bytes.fromhex(cert["enc_pub"])
    ca_pub.verify(bytes.fromhex(cert["sig"]), _cert_body(cert["name"], sp, ep, cert["exp"]))
    if cert["exp"] < (time.time() if at_time is None else at_time):
        raise ValueError("sertifikat kedaluwarsa")
    return (cert["name"], Ed25519PublicKey.from_public_bytes(sp),
            X25519PublicKey.from_public_bytes(ep))


class User:
    def __init__(self, name: str, ca: CA, ttl: int = 86400 * 30):
        self.name = name
        self.ca_pub = ca.public
        self.seen = {}                                # (pengirim, file_id) -> versi terakhir yang dilihat
        self.sign_sk = Ed25519PrivateKey.generate()   # tanda tangan (identitas)
        self.enc_sk = X25519PrivateKey.generate()     # dekripsi kunci file (penerima)
        self.cert = ca.issue(name, raw(self.sign_sk.public_key()), raw(self.enc_sk.public_key()), ttl)


# --------------------------------------------------------------------------
# 2. Format amplop + helper
# --------------------------------------------------------------------------
def _aad(header: dict) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def _kek(shared: bytes, epk: bytes, recipient_enc_pub: bytes, aad: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=epk + recipient_enc_pub,
                info=b"SSL-v1 wrap|" + aad).derive(shared)


def _signing_bytes(env: dict) -> bytes:
    return (b"SSL-SIG|" + h(_aad(env["header"]))
            + bytes.fromhex(env["epk"]) + bytes.fromhex(env["wrap_nonce"])
            + bytes.fromhex(env["wrapped_key"]) + bytes.fromhex(env["body_nonce"])
            + h(bytes.fromhex(env["ciphertext"])))


# --------------------------------------------------------------------------
# 3. Pengirim: seal_file
# --------------------------------------------------------------------------
def seal_file(sender: User, recipient_cert: dict, to: str, plaintext: bytes,
              file_id: str, version: int) -> dict:
    r_name, _, r_enc_pub = verify_cert(sender.ca_pub, recipient_cert)   # cegah kunci penerima palsu
    if r_name != to:
        raise ValueError(f"sertifikat untuk {r_name!r}, bukan {to!r}")

    header = {"v": "SSL-v1", "file_id": file_id, "version": version,
              "sender": sender.name, "recipient": r_name}
    aad = _aad(header)

    file_key, body_nonce = os.urandom(32), os.urandom(12)
    ciphertext = AESGCM(file_key).encrypt(body_nonce, plaintext, aad)

    eph = X25519PrivateKey.generate()
    epk = raw(eph.public_key())
    kek = _kek(eph.exchange(r_enc_pub), epk, raw(r_enc_pub), aad)
    wrap_nonce = os.urandom(12)
    wrapped_key = AESGCM(kek).encrypt(wrap_nonce, file_key, aad)

    env = {"header": header, "epk": epk.hex(), "wrap_nonce": wrap_nonce.hex(),
           "wrapped_key": wrapped_key.hex(), "body_nonce": body_nonce.hex(),
           "ciphertext": ciphertext.hex(), "sender_cert": sender.cert}
    env["sig"] = sender.sign_sk.sign(_signing_bytes(env)).hex()
    return env


# --------------------------------------------------------------------------
# 4. Verifikasi publik (siapa saja, termasuk pihak ketiga, tanpa perlu mendekripsi)
# --------------------------------------------------------------------------
def verify_envelope(ca_pub: Ed25519PublicKey, env: dict, at_time: float = None):
    """at_time: waktu acuan masa berlaku sertifikat pengirim. Pihak ketiga yang menilai sengketa
    setelah sertifikat kedaluwarsa memberi waktu penandatanganan yang dibuktikan secara terpisah."""
    name, sign_pub, _ = verify_cert(ca_pub, env["sender_cert"], at_time)
    if env["header"]["sender"] != name:
        raise ValueError("pengirim di header tidak sama dengan pemilik sertifikat")
    sign_pub.verify(bytes.fromhex(env["sig"]), _signing_bytes(env))     # InvalidSignature jika diubah
    return name, env["header"]


# --------------------------------------------------------------------------
# 5. Penerima: open_file
# --------------------------------------------------------------------------
def open_file(recipient: User, env: dict, expected_sender: str, expected_file_id: str):
    sender, header = verify_envelope(recipient.ca_pub, env)             # verifikasi SEBELUM dekripsi
    if sender != expected_sender:
        raise ValueError(f"pengirim {sender!r} != yang diharapkan {expected_sender!r}")
    if header["recipient"] != recipient.name:
        raise ValueError("amplop ini bukan untuk saya")
    if header["file_id"] != expected_file_id:                           # server menukar file lain
        raise ValueError(f"file_id {header['file_id']!r} != yang diminta {expected_file_id!r}")
    key = (sender, header["file_id"])
    if header["version"] < recipient.seen.get(key, 0):                  # anti-rollback per file
        raise ValueError("rollback: versi lebih lama dari yang pernah dilihat")

    aad = _aad(header)
    epk = bytes.fromhex(env["epk"])
    shared = recipient.enc_sk.exchange(X25519PublicKey.from_public_bytes(epk))
    kek = _kek(shared, epk, raw(recipient.enc_sk.public_key()), aad)
    file_key = AESGCM(kek).decrypt(bytes.fromhex(env["wrap_nonce"]),
                                   bytes.fromhex(env["wrapped_key"]), aad)
    plaintext = AESGCM(file_key).decrypt(bytes.fromhex(env["body_nonce"]),
                                         bytes.fromhex(env["ciphertext"]), aad)
    recipient.seen[key] = max(recipient.seen.get(key, 0), header["version"])   # catat HANYA setelah sukses
    return plaintext, header["version"]


if __name__ == "__main__":
    ca = CA()
    alice, bob = User("alice", ca), User("bob", ca)

    # Alice mengambil sertifikat Bob dari direktori (tidak dipercaya, tapi diverifikasi CA)
    env = seal_file(alice, bob.cert, to="bob", plaintext=b"Kontrak rahasia v1",
                    file_id="kontrak-001", version=1)
    print("Server menyimpan ciphertext:", env["ciphertext"][:40], "...")

    pt, ver = open_file(bob, env, expected_sender="alice", expected_file_id="kontrak-001")
    print(f"Bob membaca (versi {ver}):", pt.decode())
    print("Pihak ketiga memverifikasi pengirim:", verify_envelope(ca.public, env)[0])
