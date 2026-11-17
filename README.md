# SecureShare-Lite

Protokol berbagi file terenkripsi dan bertanda tangan melalui **server yang tidak dipercaya**.
Dibuat sebagai tugas *Compose System* (Security Requirements Engineering): merancang protokol sendiri
dengan alur requirement → threat → security goal → pemilihan primitive.

> **Catatan:** ini bahan belajar, **bukan** pengganti PGP, age, atau S/MIME. Jangan dipakai untuk data sungguhan.

## Skenario

```
Alice (pengirim)  ->  Server (penyimpan, tidak dipercaya)  ->  Bob (penerima)
```

Server boleh jahat: ia dapat membaca, mengubah, menukar, menghapus, dan menyajikan ulang apa pun,
termasuk direktori sertifikat. Protokol tetap harus menjaga kerahasiaan dan keaslian file.

## Isi repositori

| File | Fungsi |
|---|---|
| `secureshare.py` | Implementasi protokol (CA, sertifikat, `seal_file`, `open_file`, `verify_envelope`) beserta demo |
| `test_secureshare.py` | 14 tes pytest untuk skenario serangan dan jalur normal |
| `requirements.txt` | Dependensi (`cryptography`, `pytest`) |
| `Laporan_Checkpoint_3_SecureShare.docx` | Laporan desain lengkap, pseudocode, dan diagram alur |

## Cara menjalankan

Butuh Python 3.9 atau lebih baru.

```bash
# 1. pasang dependensi
pip install -r requirements.txt

# 2. jalankan demo (Alice mengirim, Bob membuka, pihak ketiga memverifikasi)
python secureshare.py

# 3. jalankan tes
python -m pytest -q          # hasil yang diharapkan: 14 passed
python -m pytest -v          # daftar tiap tes
```

Di Windows, `py` bisa dipakai sebagai pengganti `python` (misalnya `py -m pytest -q`).
Jalankan `pytest` dari terminal (CMD/PowerShell), bukan dari IDLE.

## Primitive kriptografi

| Tujuan | Primitive |
|---|---|
| Kerahasiaan isi file | AES-256-GCM dengan kunci file acak per file |
| Pembungkus kunci file | X25519 (ephemeral DH) + HKDF-SHA256 + AES-256-GCM (gaya ECIES/HPKE) |
| Keaslian pengirim dan non-repudiation | Ed25519 menandatangani amplop |
| Keaslian kunci publik (anti-MITM) | Sertifikat yang ditandatangani CA, `CA_pub` di-pin |
| Ringkasan ciphertext | SHA-256 |

## Cara kerja singkat

1. Alice mengambil sertifikat Bob dari direktori, memverifikasinya dengan `CA_pub`, dan memeriksa namanya.
2. Alice mengenkripsi file dengan kunci acak `K_f` (AES-256-GCM, AAD = header), lalu membungkus `K_f`
   ke kunci X25519 Bob.
3. Alice menandatangani amplop (header, kunci terbungkus, nonce, hash ciphertext) dan mengunggahnya.
4. Bob memeriksa **sebelum** mendekripsi: sertifikat pengirim, nama pengirim, penerima, `file_id`,
   tanda tangan, dan nomor versi. Baru setelah itu ia membuka `K_f` dan mendekripsi file.

## Serangan yang ditolak (dan tesnya)

| Serangan | Tes |
|---|---|
| Server membaca isi file | `test_server_cannot_read` |
| Server mengubah ciphertext | `test_server_modifies_ciphertext` |
| Server menukar kunci terbungkus | `test_server_swaps_wrapped_key` |
| Direktori memberi sertifikat dari CA palsu (MITM) | `test_mitm_forged_recipient_certificate` |
| Direktori memberi sertifikat sah milik orang lain | `test_mitm_valid_cert_wrong_recipient_name` |
| Penyamaran pengirim | `test_sender_impersonation_by_resigning`, `test_sender_cert_swapped_in_envelope` |
| Amplop dialihkan ke penerima lain | `test_retarget_to_other_recipient` |
| Server menyajikan file lain milik pengirim yang sama | `test_server_swaps_file_id` |
| Rollback ke versi lama | `test_rollback_to_old_version`, `test_rollback_is_per_file` |
| Verifikasi pihak ketiga (non-repudiation) | `test_non_repudiation_third_party`, `test_non_repudiation_after_cert_expiry` |

## Batas jaminan

- Tidak ada *forward secrecy*: jika kunci dekripsi statis Bob bocor, file lama untuk Bob dapat dibuka.
- Rollback pada unduhan pertama tidak terdeteksi, karena belum ada versi acuan.
- Server tetap melihat metadata (pengirim, penerima, ukuran, versi) dan dapat menghapus file.
- Tidak ada pencabutan (revokasi) sertifikat, dan tidak ada timestamp tepercaya.
- Keamanan bergantung pada `CA_pub` yang asli dan kunci privat yang tidak bocor.
- Di luar cakupan: banyak penerima, multi-device, dan ketersediaan layanan.

## Referensi

RFC 7748 (X25519), RFC 8032 (EdDSA), RFC 5869 (HKDF), RFC 9180 (HPKE), NIST SP 800-38D (GCM).
