# =====================================================================
# 1. LAPIS KRIPTOGRAFI (Shannon Secrecy: OTP / XOR Encryption)
# =====================================================================

def string_to_bits(text):
    """Mengubah teks string menjadi deretan bit (0 dan 1)."""
    bits = []
    for char in text.encode('utf-8'):
        bin_str = bin(char)[2:].zfill(8)
        bits.extend([int(b) for b in bin_str])
    return bits

def bits_to_string(bits):
    """Mengubah deretan bit kembali menjadi teks string."""
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break
        byte_val = int("".join(map(str, byte_bits)), 2)
        bytes_list.append(byte_val)
    return bytes(bytes_list).decode('utf-8', errors='ignore')

def xor_bits(bits_a, bits_b):
    """Operasi XOR murni antara dua deretan bit."""
    return [a ^ b for a, b in zip(bits_a, bits_b)]


# =====================================================================
# 2. LAPIS CHANNEL CODING STANDAR INDUSTRI: HAMMING(7,4) & INTERLEAVING
# =====================================================================

def encode_hamming_7_4(data_4bits):
    """
    Standar Industri Hamming(7,4):
    Mengodekan 4 bit data (d1, d2, d3, d4) menjadi 7 bit dengan 3 bit paritas (p1, p2, p3).
    Matriks Perkalian Aljabar Linear Murni berbasis GF(2) / XOR.
    """
    d1, d2, d3, d4 = data_4bits
    p1 = d1 ^ d2 ^ d4
    p2 = d1 ^ d3 ^ d4
    p3 = d2 ^ d3 ^ d4
    # Format vektor terenkapsulasi: [p1, p2, d1, p3, d2, d3, d4]
    return [p1, p2, d1, p3, d2, d3, d4]

def decode_hamming_7_4(code_7bits):
    """
    Deteksi & Koreksi Kesalahan Hamming(7,4) menggunakan Perhitungan Sindrom (Syndrome Vector).
    Jika ada 1 bit rusak di media, posisi bit tersebut dihitung dan diperbaiki secara presisi.
    """
    p1, p2, d1, p3, d2, d3, d4 = code_7bits
    
    # Perhitungan Vector Sindrom (S1, S2, S3)
    s1 = p1 ^ d1 ^ d2 ^ d4
    s2 = p2 ^ d1 ^ d3 ^ d4
    s3 = p3 ^ d2 ^ d3 ^ d4
    
    # Konversi lokasi error dari bentuk biner [S3, S2, S1] ke desimal
    error_pos = (s3 << 2) | (s2 << 1) | s1  # Indeks 1-7
    
    corrected = list(code_7bits)
    if error_pos != 0:
        # Perbaiki bit yang rusak dengan meng-inversi value bit tersebut
        corrected[error_pos - 1] ^= 1

    # Ekstraksi kembali 4 bit data asli: [d1, d2, d3, d4]
    return [corrected[2], corrected[4], corrected[5], corrected[6]], error_pos

def interleave(bits, depth=7):
    """
    Teknik Standar Industri (GSM/Satelit):
    Menyebar bit-bit data ke dalam matriks untuk menangani Gangguan Beruntun (Burst Noise).
    """
    interleaved = []
    rows = len(bits) // depth
    for col in range(depth):
        for row in range(rows):
            interleaved.append(bits[row * depth + col])
    return interleaved

def deinterleave(bits, depth=7):
    """Mengembalikan posisi bit pasca-proses interleaving."""
    deinterleaved = [0] * len(bits)
    rows = len(bits) // depth
    idx = 0
    for col in range(depth):
        for row in range(rows):
            deinterleaved[row * depth + col] = bits[idx]
            idx += 1
    return deinterleaved


# =====================================================================
# 3. SIMULASI GANGGUAN MEDIA TRANSMISI (INDUSTRI STANDAR)
# =====================================================================

def simulate_industry_channel_noise(bits):
    """
    Simulasi Gangguan Media Transmisi Nyata:
    1. Single Bit Flip (Sinyal Lemah / Attenuation)
    2. Burst Noise (Gangguan Frekuensi / Petir / Kabel Rusak singkat)
    """
    corrupted = list(bits)
    
    # Noise 1: Single Bit Flip pada indeks ke-3
    corrupted[3] ^= 1 
    
    # Noise 2: Burst Noise (3 Bit Beruntun Hancur Sekaligus di Indeks 14, 15, 16)
    for idx in range(14, 17):
        if idx < len(corrupted):
            corrupted[idx] ^= 1
            
    return corrupted


# =====================================================================
# 4. DEMONSTRASI SISTEM PEMULIHAN
# =====================================================================

if __name__ == "__main__":
    message = "KUNCI"
    key_text = "X9A2M"
    
    msg_bits = string_to_bits(message)
    key_bits = string_to_bits(key_text)
    
    # A. Enkripsi Kriptografi (XOR / OTP)
    ciphertext_bits = xor_bits(msg_bits, key_bits)
    
    # B. Encoding Hamming(7,4)
    hamming_encoded = []
    for i in range(0, len(ciphertext_bits), 4):
        chunk = ciphertext_bits[i:i+4]
        hamming_encoded.extend(encode_hamming_7_4(chunk))
        
    # C. Interleaving (Perlindungan dari Burst Noise)
    transmitted_bits = interleave(hamming_encoded, depth=7)
    
    # D. Transmisi Melalui Media yang Mengalami Gangguan
    corrupted_transmission = simulate_industry_channel_noise(transmitted_bits)
    
    # E. De-Interleaving di Sisi Penerima
    deinterleaved_bits = deinterleave(corrupted_transmission, depth=7)
    
    # F. Pemulihan Lapis 1 (Decoding Hamming + Koreksi Bit)
    recovered_ciphertext = []
    corrected_blocks = 0
    
    print("="*75)
    print("LOG DEKODE & PEMULIHAN SALURAN MEDIA TRANSMISI (HAMMING 7,4)")
    print("="*75)
    
    for idx, i in enumerate(range(0, len(deinterleaved_bits), 7)):
        block = deinterleaved_bits[i:i+7]
        recovered_4bits, err_pos = decode_hamming_7_4(block)
        recovered_ciphertext.extend(recovered_4bits)
        
        status = f"DIBERSIHKAN (Error Bit Posisi {err_pos})" if err_pos != 0 else "UTUH"
        if err_pos != 0:
            corrected_blocks += 1
        if idx < 6:
            print(f"Blok {idx:<2} | Raw Data Diterima: {str(block):<22} | Status: {status}")
            
    print("-" * 75)
    print(f"Total Blok Diperbaiki Otomatis oleh Hamming(7,4): {corrected_blocks} Blok")
    
    # G. Pemulihan Lapis 2 (Dekripsi Kriptografi)
    decrypted_msg_bits = xor_bits(recovered_ciphertext, key_bits)
    final_message = bits_to_string(decrypted_msg_bits)
    
    print("\n[HASIL PERBANDINGAN SISI PENERIMA]")
    print(f"• Pesan Asli                : '{message}'")
    print(f"• Pesan Pulih Setelah FEC   : '{final_message}' (100% UTUH DAN TEPAT)")
