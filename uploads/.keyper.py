import base64
import json
import math
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# 1. Definisi Karakter Dasar
CHARS = (
    "A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z, "
    "0, 1, 2, 3, 4, 5, 6, 7, 8, 9, ~, `, !, @, #, $, %, ^, &, *, (, ), _, -, +, =, "
    "{, [, }, }, \\, |, :, ;, ', \", <>, ?, /, "
    "a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z, "
    "😀, 😃, 😄, 😁, 😆, 😅, 😂, 🤣, 🥲, 🥹, ☺️, 😊, 😇, 🙂, 🙃, 😉, 😌, 😍, 🥰, 😘, "
    "😗, 😙, 😚, 😋, 😛, 😝, 😜, 🤪, 🤨, 🧐, 🤓, 😎, 🥸, 🤩, 🥳, 😏, 😒, 😞, 😔, "
    "😟, 😕, 🙁, ☹️, 😣, 😖, 😫, 😩, 🥺, 😢, 😭, 😮‍💨, 😤, 😠, 😡, 🤬, 🤯, 😳, 🥵, "
    "🥶, 😱, 😨, 😰, 😥, 😓, 🫣, 🤗, 🫡, 🤫, 🫠, 🤥, 😶, 😶‍🌫️, 😐, 😑, 😬, 🫥, 😯, "
    "😦, 😧, 😮, 😲, 🥱, 😴, 🤤, 😪, 😵, 😵‍💫, 🤐, 🤢, 🤮, 🤧, 😷, 🤒, 🤕, 🤑, "
    "🤠, 😈, 👿, 👹, 👺, 🤡, 💩, 👻, 💀, ☠️, 👽, 👾, 🤖, 🎃, 😺, 😸, 😹, 😻, 😼, "
    "😽, 🙀, 😿, 😾"
).split(", ")

BASE_CHAR_LIST = list(dict.fromkeys(CHARS))


def get_math_shuffled_list(key_int: int) -> list:
    """
    Mengacak urutan CHAR_LIST murni dengan matematika (Fisher-Yates berbasis Pseudo-Random LCG).
    Linear Congruential Generator (LCG): X_{n+1} = (a * X_n + c) mod m
    """
    shuffled = BASE_CHAR_LIST.copy()
    n = len(shuffled)
    
    # Konstanta LCG Matematika
    a = 1664525
    c = 1013904223
    m = 2**32
    state = key_int % m
    
    for i in range(n - 1, 0, -1):
        state = (a * state + c) % m
        j = state % (i + 1)
        # Permutasi / Swapping elemen
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
        
    return shuffled


def derive_key_math(pin_key: int, salt: bytes) -> bytes:
    """Derivasi kunci PBKDF2 murni dari PIN Integer."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(str(pin_key).encode('utf-8'))


def encrypt_custom(pesan: str, key_input: str) -> str:
    """Enkripsi menggunakan formula transformasi matematika non-linear."""
    if not key_input.isdigit():
        raise ValueError("Key harus berupa angka bulat positif!")
    key_int = int(key_input)
    if not pesan:
        raise ValueError("Pesan tidak boleh kosong!")

    char_list = get_math_shuffled_list(key_int)
    panjang_pesan = len(pesan)

    hasil_angka = []
    for pos, char in enumerate(pesan):
        if char in char_list:
            idx = char_list.index(char)
        else:
            idx = ord(char)

        # Formula Matematika Non-Linear:
        # Menambahkan komponen trigonometri/eksponensial matematis berdasarkan posisi karakter
        # delta = floor(abs(sin(pos + 1)) * 1000)
        math_delta = math.floor(abs(math.sin(pos + 1)) * 1000)
        
        nilai_akhir = idx + panjang_pesan + key_int + math_delta
        hasil_angka.append(str(nilai_akhir))

    string_gabungan = ".".join(hasil_angka)
    base32_encoded = base64.b32encode(string_gabungan.encode('utf-8')).decode('utf-8')

    # AES-256-GCM Layer
    salt = os.urandom(16)
    aes_key = derive_key_math(key_int, salt)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, base32_encoded.encode('utf-8'), None)

    payload = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

    return base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')


def decrypt_custom(encrypted_payload: str, key_input: str) -> str:
    """Dekripsi mengembalikan formula matematika ke nilai asal."""
    if not key_input.isdigit():
        raise ValueError("Key harus berupa angka bulat positif!")
    key_int = int(key_input)

    try:
        decoded_raw = base64.b64decode(encrypted_payload.encode('utf-8')).decode('utf-8')
        raw_payload = json.loads(decoded_raw)
        salt = base64.b64decode(raw_payload["salt"])
        nonce = base64.b64decode(raw_payload["nonce"])
        ciphertext = base64.b64decode(raw_payload["ciphertext"])
    except Exception:
        raise ValueError("Payload terenkripsi rusak atau format salah.")

    # AES Decrypt
    aes_key = derive_key_math(key_int, salt)
    aesgcm = AESGCM(aes_key)
    
    try:
        base32_encoded = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
    except Exception:
        raise ValueError("Gagal mendekripsi! Key salah.")

    string_gabungan = base64.b32decode(base32_encoded.encode('utf-8')).decode('utf-8')

    char_list = get_math_shuffled_list(key_int)
    angka_list = [int(x) for x in string_gabungan.split(".")]
    panjang_pesan = len(angka_list)

    pesan_asli = []
    for pos, nilai in enumerate(angka_list):
        math_delta = math.floor(abs(math.sin(pos + 1)) * 1000)
        
        # Pembalikan matematika
        idx = nilai - key_int - panjang_pesan - math_delta
        
        if 0 <= idx < len(char_list):
            pesan_asli.append(char_list[idx])
        else:
            pesan_asli.append(chr(idx))

    return "".join(pesan_asli)


if __name__ == "__main__":
    print("=== ENKRIPSI MATEMATIKA MURNI ===")
    try:
        input_key = input("Masukkan Key (Angka): ").strip()
        input_pesan = input("Masukkan Pesan: ")

        # Enkripsi
        ciphertext_result = encrypt_custom(input_pesan, input_key)
        print("\n[+] HASIL ENKRIPSI:")
        print(ciphertext_result)

        # Dekripsi
        decrypted_message = decrypt_custom(ciphertext_result, input_key)
        print(f"\n[+] HASIL DEKRIPSI: {decrypted_message}")

    except Exception as e:
        print(f"\n[!] Error: {e}")
