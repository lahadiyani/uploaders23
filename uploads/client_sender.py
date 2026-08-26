from flask import Flask, render_template_string, request, jsonify
import urllib.request
import json

app = Flask(__name__)

# =====================================================================
# LAPIS KRIPTOGRAFI & CHANNEL CODING (ENCODER & NOISE SIMULATOR)
# =====================================================================

def string_to_bits(text):
    bits = []
    for char in text.encode('utf-8'):
        bin_str = bin(char)[2:].zfill(8)
        bits.extend([int(b) for b in bin_str])
    return bits

def xor_bits(bits_a, bits_b):
    return [a ^ b for a, b in zip(bits_a, bits_b)]

def encode_hamming_7_4(data_4bits):
    d1, d2, d3, d4 = data_4bits
    p1 = d1 ^ d2 ^ d4
    p2 = d1 ^ d3 ^ d4
    p3 = d2 ^ d3 ^ d4
    return [p1, p2, d1, p3, d2, d3, d4]

def interleave(bits, depth=7):
    interleaved = []
    rows = len(bits) // depth
    for col in range(depth):
        for row in range(rows):
            interleaved.append(bits[row * depth + col])
    return interleaved

def simulate_channel_noise(bits):
    """Simulasi gangguan media: Single bit flip & burst noise."""
    corrupted = list(bits)
    if len(corrupted) > 3:
        corrupted[3] ^= 1  # Single Bit Flip
    if len(corrupted) > 16:
        for idx in range(14, 17):  # Burst Noise 3-bit beruntun
            corrupted[idx] ^= 1
    return corrupted


# =====================================================================
# FLASK CLIENT ROUTE
# =====================================================================

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Shannon Transceiver Client</title></head>
<body style="font-family: sans-serif; padding: 20px;">
    <h2>Simulasi Pengirim Data (Client Transceiver)</h2>
    <form action="/send" method="post">
        <label>Pesan Asli:</label><br>
        <input type="text" name="message" value="KUNCI" style="width: 300px; padding: 5px;"><br><br>
        <label>Kunci (Panjang Karakter Harus Sama):</label><br>
        <input type="text" name="key" value="X9A2M" style="width: 300px; padding: 5px;"><br><br>
        <button type="submit" style="padding: 8px 15px;">Enkripsi & Kirim ke Server</button>
    </form>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/send', methods=['POST'])
def send():
    message = request.form.get('message', 'KUNCI')
    key_text = request.form.get('key', 'X9A2M')

    if len(message) != len(key_text):
        return jsonify({"error": "Panjang kunci harus sama dengan panjang pesan (OTP)"}), 400

    msg_bits = string_to_bits(message)
    key_bits = string_to_bits(key_text)

    # 1. Enkripsi Kriptografi (XOR)
    ciphertext_bits = xor_bits(msg_bits, key_bits)

    # 2. Hamming(7,4) Encoding
    hamming_encoded = []
    for i in range(0, len(ciphertext_bits), 4):
        chunk = ciphertext_bits[i:i+4]
        hamming_encoded.extend(encode_hamming_7_4(chunk))

    # 3. Interleaving
    transmitted_bits = interleave(hamming_encoded, depth=7)

    # 4. Simulasi Noise Media Transmisi
    corrupted_transmission = simulate_channel_noise(transmitted_bits)

    # 5. Kirim via HTTP POST ke Receiver Server (Port 5000) tanpa library eksternal
    payload = json.dumps({
        "transmitted_bits": corrupted_transmission,
        "key_bits": key_bits
    }).encode('utf-8')

    req = urllib.request.Request(
        "http://127.0.0.1:5000/receive",
        data=payload,
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urllib.request.urlopen(req) as response:
            server_res = json.loads(response.read().decode('utf-8'))
            return jsonify({
                "client_status": "Pesan Terkirim",
                "original_message": message,
                "corrupted_bits_sent": corrupted_transmission[:21],
                "server_response": server_res
            })
    except Exception as e:
        return jsonify({"error": f"Gagal menghubungi receiver server: {str(e)}"}), 500


if __name__ == '__main__':
    print("Client Pengirim aktif pada http://127.0.0.1:5001...")
    app.run(port=5001, debug=True)
