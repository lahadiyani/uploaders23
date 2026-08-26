from flask import Flask, request, jsonify

app = Flask(__name__)

# =====================================================================
# LAPIS CHANNEL CODING (DECODER HAMMING & DE-INTERLEAVER)
# =====================================================================

def decode_hamming_7_4(code_7bits):
    """Mendeteksi dan memperbaiki bit tunggal yang rusak (Forward Error Correction)."""
    p1, p2, d1, p3, d2, d3, d4 = code_7bits
    
    # Hitung Vektor Sindrom
    s1 = p1 ^ d1 ^ d2 ^ d4
    s2 = p2 ^ d1 ^ d3 ^ d4
    s3 = p3 ^ d2 ^ d3 ^ d4
    
    error_pos = (s3 << 2) | (s2 << 1) | s1
    
    corrected = list(code_7bits)
    if error_pos != 0:
        corrected[error_pos - 1] ^= 1  # Inversi bit yang rusak

    return [corrected[2], corrected[4], corrected[5], corrected[6]], error_pos

def deinterleave(bits, depth=7):
    """Mengembalikan susunan bit dari gangguan burst noise."""
    deinterleaved = [0] * len(bits)
    rows = len(bits) // depth
    idx = 0
    for col in range(depth):
        for row in range(rows):
            deinterleaved[row * depth + col] = bits[idx]
            idx += 1
    return deinterleaved

def xor_bits(bits_a, bits_b):
    return [a ^ b for a, b in zip(bits_a, bits_b)]

def bits_to_string(bits):
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break
        byte_val = int("".join(map(str, byte_bits)), 2)
        bytes_list.append(byte_val)
    return bytes(bytes_list).decode('utf-8', errors='ignore')


# =====================================================================
# FLASK API ENDPOINT
# =====================================================================

@app.route('/receive', methods=['POST'])
def receive_data():
    payload = request.get_json()
    
    if not payload or 'transmitted_bits' not in payload or 'key_bits' not in payload:
        return jsonify({"status": "error", "message": "Payload tidak valid"}), 400

    corrupted_bits = payload['transmitted_bits']
    key_bits = payload['key_bits']

    # 1. De-interleaving
    deinterleaved_bits = deinterleave(corrupted_bits, depth=7)

    # 2. FEC / Decoding Hamming(7,4) & Perbaikan Data
    recovered_ciphertext = []
    corrected_blocks = 0
    
    for i in range(0, len(deinterleaved_bits), 7):
        block = deinterleaved_bits[i:i+7]
        recovered_4bits, err_pos = decode_hamming_7_4(block)
        recovered_ciphertext.extend(recovered_4bits)
        if err_pos != 0:
            corrected_blocks += 1

    # 3. Dekripsi Kriptografi (XOR dengan Kunci)
    decrypted_bits = xor_bits(recovered_ciphertext, key_bits)
    final_message = bits_to_string(decrypted_bits)

    print("\n[RECEIVER LOG]")
    print(f"• Total Bit Diterima (Terkontaminasi) : {len(corrupted_bits)} bit")
    print(f"• Blok Diperbaiki oleh Hamming(7,4)   : {corrected_blocks} blok")
    print(f"• Hasil Dekripsi Akhir                 : '{final_message}'\n")

    return jsonify({
        "status": "success",
        "recovered_message": final_message,
        "corrected_blocks_count": corrected_blocks
    }), 200


if __name__ == '__main__':
    print("Server Penerima aktif pada http://127.0.0.1:5000...")
    app.run(port=5000, debug=True)
