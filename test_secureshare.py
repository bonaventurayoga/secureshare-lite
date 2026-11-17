"""Tes SecureShare-Lite. Jalankan: python -m pytest -q"""
import copy
import time
import pytest
from cryptography.exceptions import InvalidSignature
from secureshare import CA, User, seal_file, open_file, verify_envelope


def setup():
    ca = CA()
    return ca, User("alice", ca), User("bob", ca), User("carol", ca)


def test_normal_share():
    ca, a, b, c = setup()
    env = seal_file(a, b.cert, "bob", b"isi rahasia", "f1", 1)
    pt, ver = open_file(b, env, "alice", "f1")
    assert pt == b"isi rahasia" and ver == 1


def test_server_cannot_read():
    ca, a, b, c = setup()
    env = seal_file(a, b.cert, "bob", b"PASSWORD=hunter2", "f1", 1)
    assert b"hunter2" not in bytes.fromhex(env["ciphertext"])


def test_server_modifies_ciphertext():
    ca, a, b, c = setup()
    env = seal_file(a, b.cert, "bob", b"transfer 10", "f1", 1)
    bad = copy.deepcopy(env)
    ct = bytearray(bytes.fromhex(bad["ciphertext"])); ct[0] ^= 1
    bad["ciphertext"] = ct.hex()
    with pytest.raises(InvalidSignature):
        open_file(b, bad, "alice", "f1")


def test_server_swaps_wrapped_key():
    ca, a, b, c = setup()
    env1 = seal_file(a, b.cert, "bob", b"file 1", "f1", 1)
    env2 = seal_file(a, b.cert, "bob", b"file 2", "f1", 1)
    bad = copy.deepcopy(env1)
    bad["wrapped_key"], bad["epk"], bad["wrap_nonce"] = env2["wrapped_key"], env2["epk"], env2["wrap_nonce"]
    with pytest.raises(InvalidSignature):
        open_file(b, bad, "alice", "f1")


def test_mitm_forged_recipient_certificate():
    """Direktori jahat memberi Alice sertifikat 'bob' dari CA palsu -> Alice menolak mengenkripsi."""
    ca, a, b, c = setup()
    fake = User("bob", CA())
    with pytest.raises(InvalidSignature):
        seal_file(a, fake.cert, "bob", b"rahasia", "f1", 1)


def test_mitm_valid_cert_wrong_recipient_name():
    """Direktori memberi sertifikat SAH tetapi milik 'carol' saat Alice meminta 'bob'."""
    ca, a, b, c = setup()
    with pytest.raises(ValueError):
        seal_file(a, c.cert, "bob", b"rahasia", "f1", 1)


def test_sender_impersonation_by_resigning():
    """Mallory (sertifikat sah atas nama 'mallory') mengirim ke Bob seolah-olah Alice."""
    ca, a, b, c = setup()
    m = User("mallory", ca)
    env = seal_file(m, b.cert, "bob", b"transfer ke mallory", "f1", 1)
    with pytest.raises(ValueError):
        open_file(b, env, "alice", "f1")


def test_sender_cert_swapped_in_envelope():
    """Mallory mengambil amplop Alice lalu mengganti sertifikat pengirim dengan miliknya."""
    ca, a, b, c = setup()
    m = User("mallory", ca)
    env = seal_file(a, b.cert, "bob", b"asli", "f1", 1)
    bad = copy.deepcopy(env); bad["sender_cert"] = m.cert
    with pytest.raises(ValueError):
        open_file(b, bad, "alice", "f1")


def test_retarget_to_other_recipient():
    ca, a, b, c = setup()
    env = seal_file(a, b.cert, "bob", b"hanya untuk bob", "f1", 1)
    with pytest.raises(ValueError):
        open_file(c, env, "alice", "f1")                    # Carol menerima amplop Bob
    bad = copy.deepcopy(env); bad["header"]["recipient"] = "carol"
    with pytest.raises(InvalidSignature):
        open_file(c, bad, "alice", "f1")                    # header diubah -> tanda tangan gagal


def test_rollback_to_old_version():
    ca, a, b, c = setup()
    v1 = seal_file(a, b.cert, "bob", b"kontrak v1", "k", 1)
    v2 = seal_file(a, b.cert, "bob", b"kontrak v2", "k", 2)
    open_file(b, v2, "alice", "k")
    with pytest.raises(ValueError):
        open_file(b, v1, "alice", "k")                     # server menyajikan versi lama


def test_server_swaps_file_id():
    """Server menyajikan amplop SAH file lain dari Alice saat Bob meminta 'f1'."""
    ca, a, b, c = setup()
    other = seal_file(a, b.cert, "bob", b"file lain", "f2", 1)
    with pytest.raises(ValueError):
        open_file(b, other, "alice", "f1")
    assert b.seen == {}                                    # gagal -> versi tidak tercatat


def test_rollback_is_per_file():
    """Versi tinggi pada file A tidak boleh membuat file B versi 1 dianggap rollback."""
    ca, a, b, c = setup()
    open_file(b, seal_file(a, b.cert, "bob", b"A v5", "A", 5), "alice", "A")
    pt, ver = open_file(b, seal_file(a, b.cert, "bob", b"B v1", "B", 1), "alice", "B")
    assert pt == b"B v1" and ver == 1
    with pytest.raises(ValueError):                        # tetap menolak rollback pada file A
        open_file(b, seal_file(a, b.cert, "bob", b"A v4", "A", 4), "alice", "A")


def test_non_repudiation_after_cert_expiry():
    """Sertifikat sudah kedaluwarsa: ditolak jika dinilai 'sekarang', tapi bukti tetap dapat
    diverifikasi pada waktu penandatanganan (at_time) oleh pihak ketiga."""
    ca = CA()
    a, b = User("alice", ca, ttl=-10), User("bob", ca)
    env = seal_file(a, b.cert, "bob", b"kontrak", "k", 1)
    with pytest.raises(ValueError):
        verify_envelope(ca.public, env)
    sender, _ = verify_envelope(ca.public, env, at_time=time.time() - 100)
    assert sender == "alice"


def test_non_repudiation_third_party():
    """Pihak ketiga memverifikasi pengirim hanya dengan CA_pub, tanpa mendekripsi."""
    ca, a, b, c = setup()
    env = seal_file(a, b.cert, "bob", b"kontrak", "k", 1)
    sender, header = verify_envelope(ca.public, env)
    assert sender == "alice" and header["recipient"] == "bob"
    bad = copy.deepcopy(env); bad["header"]["version"] = 9
    with pytest.raises(InvalidSignature):
        verify_envelope(ca.public, bad)


if __name__ == "__main__":
    raise SystemExit(pytest.main(["-q", __file__]))
