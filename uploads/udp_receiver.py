import socket
import json

# =====================================================================
# LAPIS CHANNEL CODING & FEC RECOVERY (PARITY / XOR FEC)
# =====================================================================

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
# UDP RECEIVER SERVER
# =====================================================================

UDP_IP = "127.0.0.1"
UDP_PORT = 5000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"[SERVER] UDP Receiver aktif mendengarkan di {UDP_IP}:{UDP_PORT}...\n")

received_packets = {}
total_expected_packets = None
key_bits = None

while True:
    data, addr = sock.recvfrom(2048)
    packet = json.loads(data.decode('utf-8'))
    
    seq_num = packet["seq_num"]
    total_expected_packets = packet["total_packets"]
    key_bits = packet["key_bits"]
    
    received_packets[seq_num] = packet["payload"]
    print(f"[RECEIVER] Paket #{seq_num} diterima dari {addr}")
    
    # Jika semua paket yang sampai telah dikumpulkan (atau timeout tercapai)
    if len(received_packets) >= total_expected_packets - 1:
        print("\n" + "="*60)
        print("MOMEN REKONSTRUKSI PACKET LOSS (SHANNON FEC)")
        print("="*60)
        
        missing_seq = None
        for i in range(total_expected_packets):
            if i not in received_packets:
                missing_seq = i
                break
        
        if missing_seq is None:
            print("• Status: Semua paket diterima lengkap (0% Packet Loss).")
            recovered_ciphertext = []
            for i in range(total_expected_packets - 1): # Abaikan paket Paritas
                recovered_ciphertext.extend(received_packets[i])
        else:
            print(f"• WARNING: Paket #{missing_seq} HILANG / TERBUANG DI JARINGAN!")
            print(f"• Memulai pemulihan matematis XOR Parity...")
            
            # Algoritma Rekonstruksi Paritas: A ^ B ^ Parity = Paket Hilang
            reconstructed_packet = list(received_packets[list(received_packets.keys())[0]])
            for seq, payload in received_packets.items():
                if seq != list(received_packets.keys())[0]:
                    reconstructed_packet = xor_bits(reconstructed_packet, payload)
            
            received_packets[missing_seq] = reconstructed_packet
            print(f"• Paket #{missing_seq} BERHASIL DIPULIHKAN 100% dari Paritas!")
            
            recovered_ciphertext = []
            for i in range(total_expected_packets - 1):
                recovered_ciphertext.extend(received_packets[i])
                
        # Dekripsi OTP
        decrypted_bits = xor_bits(recovered_ciphertext, key_bits)
        final_message = bits_to_string(decrypted_bits)
        print(f"\n[HASIL AKHIR] Pesan Berhasil Dekripsi: '{final_message}'")
        print("="*60 + "\n")
        break
