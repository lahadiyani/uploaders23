import base64
import json
import math
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
    shuffled = BASE_CHAR_LIST.copy()
    n = len(shuffled)

    a = 1664525
    c = 1013904223
    m = 2**32
    state = key_int % m

    for i in range(n - 1, 0, -1):
        state = (a * state + c) % m
        j = state % (i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

    return shuffled


def derive_key_math(pin_key: int, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(str(pin_key).encode('utf-8'))


def decrypt_custom(encrypted_payload: str, key_input: str) -> str:
    """Mendekripsi payload terenkripsi kembali ke teks asli."""
    if not key_input.isdigit():
        raise ValueError("Key harus berupa angka bulat positif!")
    key_int = int(key_input)

    # 1. Parsing JSON & Base64 Payload (DI-FIX: Menggunakan b64decode, bukan b32decode)
    try:
        decoded_raw = base64.b64decode(encrypted_payload.strip().encode('utf-8')).decode('utf-8')
        raw_payload = json.loads(decoded_raw)
        salt = base64.b64decode(raw_payload["salt"])
        nonce = base64.b64decode(raw_payload["nonce"])
        ciphertext = base64.b64decode(raw_payload["ciphertext"])
    except Exception as e:
        raise ValueError("Format payload terenkripsi tidak valid atau rusak.")

    # 2. Dekripsi AES-256-GCM
    aes_key = derive_key_math(key_int, salt)
    aesgcm = AESGCM(aes_key)

    try:
        base32_encoded = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
    except Exception:
        raise ValueError("Gagal mendekripsi! Key (PIN) yang Anda masukkan salah.")

    # 3. Reversi Transformasi Matematika Non-Linear
    string_gabungan = base64.b32decode(base32_encoded.encode('utf-8')).decode('utf-8')
    char_list = get_math_shuffled_list(key_int)
    angka_list = [int(x) for x in string_gabungan.split(".")]
    panjang_pesan = len(angka_list)

    pesan_asli = []
    for pos, nilai in enumerate(angka_list):
        math_delta = math.floor(abs(math.sin(pos + 1)) * 1000)
        idx = nilai - key_int - panjang_pesan - math_delta

        if 0 <= idx < len(char_list):
            pesan_asli.append(char_list[idx])
        else:
            pesan_asli.append(chr(idx))

    return "".join(pesan_asli)


if __name__ == "__main__":
    print("=== DECODER TOOL ===")
    try:
        input_key = input("Masukkan Key (Angka): ").strip()
        input_payload = input("Masukkan Encrypted Payload: ").strip()

        decrypted_message = decrypt_custom(input_payload, input_key)
        print("\n[+] HASIL DEKRIPSI:")
        print(decrypted_message)

    except Exception as e:
        print(f"\n[!] Error: {e}")
