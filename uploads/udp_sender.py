import socket
import json
import random
import time

# =====================================================================
# LAPIS KRIPTOGRAFI & FEC ENCODER
# =====================================================================

def string_to_bits(text):
    bits = []
    for char in text.encode('utf-8'):
        bin_str = bin(char)[2:].zfill(8)
        bits.extend([int(b) for b in bin_str])
    return bits

def xor_bits(bits_a, bits_b):
    return [a ^ b for a, b in zip(bits_a, bits_b)]

# =====================================================================
# UDP SENDER CLIENT (WITH REAL PACKET LOSS SIMULATOR)
# =====================================================================

UDP_IP = "127.0.0.1"
UDP_PORT = 5000

message = "KUNCI KRIPTOGRAFI"
key_text = "X9A2M1B3C4D5E6F7G"  # Panjang disesuaikan

msg_bits = string_to_bits(message)
key_bits = string_to_bits(key_text)[:len(msg_bits)]

# 1. Enkripsi OTP
ciphertext_bits = xor_bits(msg_bits, key_bits)

# 2. Pemecahan Paket Data (Datagram Fragmentation)
chunk_size = len(ciphertext_bits) // 3
p0 = ciphertext_bits[0:chunk_size]
p1 = ciphertext_bits[chunk_size:chunk_size*2]
p2 = ciphertext_bits[chunk_size*2:]

# 3. Buat Paket Paritas Cadangan (FEC = P0 ^ P1 ^ P2)
parity_fec = xor_bits(xor_bits(p0, p1), p2)

packets = [p0, p1, p2, parity_fec] # Total 4 paket
total_packets = len(packets)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 4. SIMULASI REAL PACKET LOSS (Dibatalkan Pengirimannya di Jaringan)
DROP_PACKET_INDEX = 1  # Kita sengaja MEMBUANG Paket #1 di jalan!

print(f"[CLIENT] Mengirim {total_packets} Paket UDP ke Server...")

for seq_num, payload in enumerate(packets):
    if seq_num == DROP_PACKET_INDEX:
        print(f"[NETWORK SIMULATOR] ---> PAKET #{seq_num} TERBUANG (PACKET LOSS DI JARINGAN) <---")
        continue # Paket ini tidak pernah sampai ke socket kabel jaringan!
        
    packet_data = {
        "seq_num": seq_num,
        "total_packets": total_packets,
        "key_bits": key_bits,
        "payload": payload
    }
    
    sock.sendto(json.dumps(packet_data).encode('utf-8'), (UDP_IP, UDP_PORT))
    print(f"[CLIENT] Paket #{seq_num} berhasil terkirim via UDP.")
    time.sleep(0.1) # Jeda waktu antar paket
