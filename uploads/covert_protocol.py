#!/usr/bin/env python3
"""
COVERT TRANSPORT PROTOCOL - Core Library
==========================================
Military/Space-grade covert channel menggabungkan:
1. ICMPv6 Port Unreachable (Kamuflase Respon)
2. Shannon One-Time Pad (Perfect Secrecy) 
3. FEC Hamming(7,4) + Interleaving (Error Correction)

Mathematical Foundation:
- P(M=m|C=c) = P(M=m)  [Shannon 1949]
- v = d · G (mod 2)    [Hamming Encoding over GF(2)]
- s = H · r^T (mod 2)  [Syndrome Calculation]
"""

import os
import struct
import hashlib
import json
import threading
from typing import Optional, Tuple, List
from collections import defaultdict

# ==============================================================================
# LAYER 1: SHANNON ONE-TIME PAD - PERFECT SECRECY
# ==============================================================================
class ShannonOTP:
    """
    Implementasi murni Shannon One-Time Pad
    
    Teori Information-Theoretic Security (Shannon, 1949):
    ┌─────────────────────────────────────────────────────────────┐
    │  P(M = m | C = c) = P(M = m)                               │
    │                                                             │
    │  Artinya: Ciphertext TIDAK memberikan informasi apapun      │
    │  tentang plaintext. Bahkan komputer kuantum tidak bisa      │
    │  membedakan dekripsi mana yang "benar".                     │
    │                                                             │
    │  Properti:                                                  │
    │  - C_i = P_i ⊕ K_i (XOR bit-by-bit)                        │
    │  - Kunci harus sepanjang plaintext                          │
    │  - Kunci hanya boleh dipakai SEKALI (One-Time)             │
    │  - Kunci harus Truly Random (CSPRNG)                        │
    │  - Output memiliki distribusi uniform p=0.5 per bit         │
    │    → Zero Entropy Anomaly terhadap DPI/Cryptanalysis        │
    └─────────────────────────────────────────────────────────────┘
    """
    
    @staticmethod
    def generate_key(length: int) -> bytes:
        """
        Generate kunci acak menggunakan OS CSPRNG (/dev/urandom)
        Kunci HARUS sepanjang plaintext untuk Perfect Secrecy
        """
        return os.urandom(length)
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        """
        Enkripsi XOR murni: C_i = P_i ⊕ K_i
        
        Mathematical guarantee:
        Untuk setiap ciphertext c dan plaintext m dengan P(M=m) > 0,
        terdapat tepat SATU kunci k sehingga Enc_k(m) = c
        """
        if len(key) < len(plaintext):
            raise ValueError(
                f"OTP VIOLATION: Key length ({len(key)}) < Plaintext length ({len(plaintext)}). "
                f"Perfect Secrecy REQUIRES key length >= plaintext length."
            )
        return bytes(p ^ k for p, k in zip(plaintext, key))
    
    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes) -> bytes:
        """
        Dekripsi OTP identik dengan enkripsi (XOR adalah operasi involutory)
        Dec_k(C) = C ⊕ K = (P ⊕ K) ⊕ K = P
        """
        return ShannonOTP.encrypt(ciphertext, key)


# ==============================================================================
# LAYER 2A: FEC HAMMING(7,4) OVER GF(2)
# ==============================================================================
class Hamming74:
    """
    Kode Hamming(7,4) menggunakan Aljabar Linear di Galois Field GF(2)
    
    ┌─────────────────────────────────────────────────────────────┐
    │  SPESIFIKASI KODE:                                         │
    │  - n = 7 (panjang codeword)                                │
    │  - k = 4 (panjang data)                                    │
    │  - r = 3 (panjang parity)                                  │
    │  - d_min = 3 (minimum Hamming distance)                    │
    │                                                             │
    │  KAPASITAS KOREKSI:                                         │
    │  - Mendeteksi hingga 2 bit error                           │
    │  - Mengoreksi 1 bit error (Single-Bit Error Correction)    │
    │                                                             │
    │  MATRIKS (Standard Form):                                  │
    │  Generator: G = [I₄ | P]    Parity Check: H = [Pᵀ | I₃]   │
    └─────────────────────────────────────────────────────────────┘
    
    Encoding: v = d · G (mod 2)
    Syndrome: s = H · r^T (mod 2)
    
    Jika s = 0: Tidak ada error
    Jika s ≠ 0: s menunjuk ke lokasi bit error → Flip bit tersebut
    """
    
    # Generator Matrix G (4×7) - Standard Form [I₄ | P]
    # Baris = koefisien untuk setiap bit data
    G = [
        [1, 0, 0, 0, 1, 1, 0],  # d₀ → v = d₀[1,0,0,0,1,1,0]
        [0, 1, 0, 0, 1, 0, 1],  # d₁
        [0, 0, 1, 0, 0, 1, 1],  # d₂
        [0, 0, 0, 1, 1, 1, 1],  # d₃
    ]
    
    # Parity Check Matrix H (3×7) - Standard Form [Pᵀ | I₃]
    # Digunakan untuk menghitung syndrome
    H = [
        [1, 1, 0, 1, 1, 0, 0],  # Parity bit p₀
        [1, 0, 1, 1, 0, 1, 0],  # Parity bit p₁
        [0, 1, 1, 1, 0, 0, 1],  # Parity bit p₂
    ]
    
    # Syndrome → Error Position Mapping
    # Setiap kolom H adalah representasi biner posisi error
    SYNDROME_TO_POSITION = {
        (0, 0, 0): -1,  # Tidak ada error
        (1, 1, 0): 0,   # Error di bit posisi 0
        (1, 0, 1): 1,   # Error di bit posisi 1
        (0, 1, 1): 2,   # Error di bit posisi 2
        (1, 1, 1): 3,   # Error di bit posisi 3
        (1, 0, 0): 4,   # Error di bit posisi 4 (parity)
        (0, 1, 0): 5,   # Error di bit posisi 5 (parity)
        (0, 0, 1): 6,   # Error di bit posisi 6 (parity)
    }
    
    @classmethod
    def _matrix_mult_gf2(cls, row_vector: List[int], matrix: List[List[int]]) -> List[int]:
        """
        Perkalian matriks di GF(2): result = row · matrix (mod 2)
        Setiap operasi aritmatika diambil modulo 2
        """
        n_cols = len(matrix[0])
        result = []
        for j in range(n_cols):
            # Dot product di GF(2): sum of (a_i * b_ij) mod 2
            val = sum(row_vector[i] * matrix[i][j] for i in range(len(row_vector))) % 2
            result.append(val)
        return result
    
    @classmethod
    def encode(cls, data_bits: List[int]) -> List[int]:
        """
        Encode 4 bit data menjadi 7 bit codeword
        
        Proses: v = d · G (mod 2)
        
        Contoh: d = [1, 0, 1, 1]
        v = [1,0,1,1] · G = [1,0,1,1,0,1,0]
        
        Bit 0-3: Data asli
        Bit 4-6: Parity bits (redundansi untuk koreksi error)
        """
        if len(data_bits) != 4:
            raise ValueError(f"Hamming(7,4) requires exactly 4 data bits, got {len(data_bits)}")
        return cls._matrix_mult_gf2(data_bits, cls.G)
    
    @classmethod
    def decode(cls, received: List[int]) -> Tuple[List[int], bool, int]:
        """
        Decode 7 bit received dengan Single-Bit Error Correction
        
        Proses:
        1. Hitung syndrome: s = H · r^T (mod 2)
        2. Jika s = (0,0,0): Tidak ada error, return data bits
        3. Jika s ≠ (0,0,0): 
           - Lookup table untuk menemukan posisi error
           - Flip bit di posisi tersebut (XOR dengan 1)
           - Return corrected data bits
        
        Returns:
            (decoded_4_bits, was_corrected, error_position)
            - error_position = -1: no error
            - error_position = 0-6: corrected at this position
            - error_position = -2: uncorrectable (2+ bit errors)
        """
        if len(received) != 7:
            raise ValueError(f"Hamming(7,4) requires exactly 7 received bits, got {len(received)}")
        
        # Step 1: Calculate syndrome s = H · r^T (mod 2)
        syndrome = tuple(cls._matrix_mult_gf2(received, cls.H))
        
        # Step 2: Lookup error position
        error_pos = cls.SYNDROME_TO_POSITION.get(syndrome, -2)
        
        # Step 3: Correct or return
        if error_pos == -1:
            # No error detected
            return received[:4], False, -1
        elif error_pos >= 0:
            # Single-bit error detected and correctable
            corrected = received.copy()
            corrected[error_pos] ^= 1  # Flip the error bit
            return corrected[:4], True, error_pos
        else:
            # Multiple bit error (syndrome not in lookup table)
            # Cannot correct - return as-is
            return received[:4], False, -2


# ==============================================================================
# LAYER 2B: INTERLEAVER (DEPTH = 7)
# ==============================================================================
class Interleaver:
    """
    Block Interleaver dengan kedalaman 7
    
    ┌─────────────────────────────────────────────────────────────┐
    │  TUJUAN: Menyebarkan Burst Errors menjadi Single-Bit Errors│
    │                                                             │
    │  Masalah:                                                   │
    │  DPI atau noise jaringan sering menyebabkan BURST ERROR    │
    │  (beberapa bit berurutan rusak sekaligus)                  │
    │  Contoh: bit 14, 15, 16 hancur → Hamming tidak bisa koreksi│
    │                                                             │
    │  Solusi Interleaving:                                       │
    │  1. Bit-bit dari blok yang sama disebar ke lokasi jauh     │
    │  2. Saat burst error terjadi, error tersebar ke blok lain  │
    │  3. Setelah de-interleave, tiap blok hanya punya 1 bit err│
    │  4. Hamming(7,4) bisa mengoreksi semua error!              │
    │                                                             │
    │  Contoh dengan Depth=7:                                     │
    │  Input:  [b0,b1,b2,b3,b4,b5,b6,b7,b8,...]                 │
    │  Matrix: ┌─────────────────┐                               │
    │          │ b0 b1 b2 b3 b4 b5 b6 │  (Row 0)                │
    │          │ b7 b8 b9 b10...     │  (Row 1)                │
    │          └─────────────────┘                               │
    │  Output: [b0,b7,...,b1,b8,...,b2,b9,...] (Column-major)   │
    │                                                             │
    │  Burst error di output → tersebar saat dibaca row-major    │
    └─────────────────────────────────────────────────────────────┘
    """
    
    DEPTH = 7  # Harus sama dengan panjang codeword Hamming(7,4)
    
    @classmethod
    def interleave(cls, bit_stream: List[int]) -> Tuple[List[int], int]:
        """
        Interleave bit stream dengan depth 7
        
        Proses:
        1. Pad bit stream ke multiple of DEPTH
        2. Bentuk matrix baris-major (DEPTH kolom)
        3. Baca column-major (transpose)
        
        Returns:
            (interleaved_bits, padding_count)
        """
        n = len(bit_stream)
        
        # Pad ke multiple of DEPTH
        padding = (cls.DEPTH - (n % cls.DEPTH)) % cls.DEPTH
        padded = bit_stream + [0] * padding
        
        rows = len(padded) // cls.DEPTH
        
        # Create row-major matrix
        matrix = [padded[i*cls.DEPTH:(i+1)*cls.DEPTH] for i in range(rows)]
        
        # Read column-major (transpose and flatten)
        interleaved = []
        for col in range(cls.DEPTH):
            for row in range(rows):
                interleaved.append(matrix[row][col])
        
        return interleaved, padding
    
    @classmethod
    def deinterleave(cls, bit_stream: List[int], padding: int = 0) -> List[int]:
        """
        Deinterleave bit stream (inverse of interleave)
        
        Proses:
        1. Bentuk matrix column-major (isi per kolom)
        2. Baca row-major
        3. Hapus padding
        
        Returns:
            original_bit_stream (tanpa padding)
        """
        n = len(bit_stream)
        rows = n // cls.DEPTH
        
        # Reconstruct matrix from column-major order
        matrix = [[0] * cls.DEPTH for _ in range(rows)]
        idx = 0
        for col in range(cls.DEPTH):
            for row in range(rows):
                if idx < n:
                    matrix[row][col] = bit_stream[idx]
                    idx += 1
        
        # Read row-major
        deinterleaved = []
        for row in range(rows):
            deinterleaved.extend(matrix[row])
        
        # Remove padding
        if padding > 0 and len(deinterleaved) >= padding:
            deinterleaved = deinterleaved[:-padding]
        
        return deinterleaved


# ==============================================================================
# LAYER 3: COVERT PROTOCOL ENGINE (Full Stack)
# ==============================================================================
class CovertProtocol:
    """
    Full Protocol Stack Implementation
    
    ┌─────────────────────────────────────────────────────────────┐
    │                   ENCODING PIPELINE                        │
    │                                                             │
    │  [Plaintext]                                                │
    │       │                                                     │
    │       ▼ (1) Shannon OTP Encryption                         │
    │  [Ciphertext - Zero Signature, Uniform Distribution]       │
    │       │                                                     │
    │       ▼ (2) Hamming(7,4) Encoding                          │
    │  [Error-Protected Bits - 4→7 expansion]                    │
    │       │                                                     │
    │       ▼ (3) Interleaving (Depth 7)                         │
    │  [Burst-Resistant Stream]                                  │
    │       │                                                     │
    │       ▼ (4) ICMPv6 Encapsulation                           │
    │  [Covert Packet]                                           │
    │                                                             │
    ├─────────────────────────────────────────────────────────────┤
    │                   DECODING PIPELINE                        │
    │                                                             │
    │  [Covert Packet]                                           │
    │       │                                                     │
    │       ▼ (1) ICMPv6 Extraction                              │
    │       │                                                     │
    │       ▼ (2) Deinterleaving                                 │
    │       │                                                     │
    │       ▼ (3) Hamming(7,4) Decoding + Error Correction      │
    │       │                                                     │
    │       ▼ (4) Shannon OTP Decryption                         │
    │  [Plaintext]                                                │
    └─────────────────────────────────────────────────────────────┘
    
    Protocol Header Format (3 bytes):
    ┌───────────────────────────────────────────────────────────┐
    │ Byte 0: [VERSION:4bits][INTERLEAVE_PADDING:4bits]        │
    │ Byte 1-2: [ORIGINAL_BIT_LENGTH:16bits]                   │
    └───────────────────────────────────────────────────────────┘
    """
    
    PROTOCOL_VERSION = 0x01
    HEADER_SIZE = 3
    MAX_PAYLOAD = 1200  # Max encoded bytes per packet
    
    @classmethod
    def _bytes_to_bits(cls, data: bytes) -> List[int]:
        """Convert bytes to bit array (MSB first per byte)"""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits
    
    @classmethod
    def _bits_to_bytes(cls, bits: List[int]) -> bytes:
        """Convert bit array to bytes (MSB first per byte)"""
        # Pad to multiple of 8
        padding = (8 - len(bits) % 8) % 8
        bits = bits + [0] * padding
        
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            result.append(byte)
        return bytes(result)
    
    @classmethod
    def encode(cls, plaintext: bytes, otp_key: bytes) -> bytes:
        """
        Full encoding pipeline
        
        Args:
            plaintext: Original message bytes
            otp_key: One-time pad key (must be >= len(plaintext))
            
        Returns:
            Protocol header + encoded data
        """
        # ═══════════════════════════════════════════════════════════
        # STEP 1: Shannon OTP Encryption (Perfect Secrecy)
        # Output: Ciphertext dengan distribusi uniform p=0.5
        # ═══════════════════════════════════════════════════════════
        ciphertext = ShannonOTP.encrypt(plaintext, otp_key)
        
        # Convert to bits for FEC processing
        bits = cls._bytes_to_bits(ciphertext)
        original_bit_len = len(bits)
        
        # ═══════════════════════════════════════════════════════════
        # STEP 2: Hamming(7,4) Encoding
        # Input:  4 bit data
        # Output: 7 bit codeword (redundansi 75%)
        # ═══════════════════════════════════════════════════════════
        hamming_bits = []
        for i in range(0, len(bits), 4):
            chunk = bits[i:i+4]
            # Pad chunk jika tidak genap 4
            if len(chunk) < 4:
                chunk = chunk + [0] * (4 - len(chunk))
            hamming_bits.extend(Hamming74.encode(chunk))
        
        # ═══════════════════════════════════════════════════════════
        # STEP 3: Interleaving (Depth 7)
        # Menyebarkan burst error ke multiple Hamming blocks
        # ═══════════════════════════════════════════════════════════
        interleaved, interleaving_padding = Interleaver.interleave(hamming_bits)
        
        # Convert back to bytes
        encoded_bytes = cls._bits_to_bytes(interleaved)
        
        # ═══════════════════════════════════════════════════════════
        # STEP 4: Create Protocol Header
        # ═══════════════════════════════════════════════════════════
        header_byte = (cls.PROTOCOL_VERSION << 4) | (interleaving_padding & 0x0F)
        header = struct.pack('>B H', header_byte, original_bit_len)
        
        return header + encoded_bytes
    
    @classmethod
    def decode(cls, encoded_data: bytes, otp_key: bytes) -> Tuple[Optional[bytes], dict]:
        """
        Full decoding pipeline dengan error correction
        
        Args:
            encoded_data: Protocol header + encoded bytes
            otp_key: One-time pad key (must be >= original plaintext length)
            
        Returns:
            (plaintext_or_none, metadata_dict)
        """
        metadata = {
            'errors_corrected': 0,
            'uncorrectable_errors': 0,
            'total_blocks': 0,
            'protocol_version': None,
            'original_bit_len': 0,
            'interleaving_padding': 0,
        }
        
        if len(encoded_data) < cls.HEADER_SIZE:
            return None, metadata
        
        # ═══════════════════════════════════════════════════════════
        # STEP 1: Parse Protocol Header
        # ═══════════════════════════════════════════════════════════
        header_byte = encoded_data[0]
        protocol_version = (header_byte >> 4) & 0x0F
        interleaving_padding = header_byte & 0x0F
        original_bit_len = struct.unpack('>H', encoded_data[1:3])[0]
        
        metadata['protocol_version'] = protocol_version
        metadata['original_bit_len'] = original_bit_len
        metadata['interleaving_padding'] = interleaving_padding
        
        if protocol_version != cls.PROTOCOL_VERSION:
            return None, metadata
        
        encoded_bytes = encoded_data[cls.HEADER_SIZE:]
        
        # ═══════════════════════════════════════════════════════════
        # STEP 2: Deinterleaving
        # Mengembalikan bit stream ke urutan asli
        # Burst error terpecah menjadi single-bit errors
        # ═══════════════════════════════════════════════════════════
        bits = cls._bytes_to_bits(encoded_bytes)
        deinterleaved = Interleaver.deinterleave(bits)
        
        # ═══════════════════════════════════════════════════════════
        # STEP 3: Hamming(7,4) Decoding dengan Error Correction
        # Self-Healing Data: otomatis koreksi single-bit errors
        # ═══════════════════════════════════════════════════════════
        decoded_bits = []
        for i in range(0, len(deinterleaved), 7):
            chunk = deinterleaved[i:i+7]
            if len(chunk) == 7:
                metadata['total_blocks'] += 1
                data_bits, corrected, error_pos = Hamming74.decode(chunk)
                
                if corrected:
                    metadata['errors_corrected'] += 1
                elif error_pos == -2:
                    metadata['uncorrectable_errors'] += 1
                
                decoded_bits.extend(data_bits)
        
        # Trim to original bit length
        decoded_bits = decoded_bits[:original_bit_len]
        
        # Convert to bytes
        ciphertext = cls._bits_to_bytes(decoded_bits)
        
        # ═══════════════════════════════════════════════════════════
        # STEP 4: Shannon OTP Decryption
        # ═══════════════════════════════════════════════════════════
        try:
            plaintext = ShannonOTP.decrypt(ciphertext, otp_key)
            return plaintext, metadata
        except Exception:
            return None, metadata


# ==============================================================================
# LAYER 4: KEY MANAGEMENT
# ==============================================================================
class OTPKeyManager:
    """
    Manajemen kunci OTP untuk Perfect Secrecy
    
    PERINGATAN: Untuk TRUE OTP, kunci HARUS:
    1. Di-generate menggunakan Truly Random Number Generator
    2. Panjangnya sama dengan plaintext
    3. Hanya digunakan SEKALI
    4. Dibagikan melalui channel yang aman (out-of-band)
    
    Implementasi ini menggunakan two approaches:
    1. Pre-shared key pool (TRUE OTP)
    2. Key derivation dari shared secret (Praktis, tapi TIDAK true OTP)
    """
    
    KEY_POOL_FILE = "otp_key_pool.json"
    lock = threading.Lock()
    
    @classmethod
    def _load_pool(cls) -> dict:
        if not os.path.exists(cls.KEY_POOL_FILE):
            return {}
        try:
            with open(cls.KEY_POOL_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    
    @classmethod
    def _save_pool(cls, pool: dict):
        with open(cls.KEY_POOL_FILE, 'w') as f:
            json.dump(pool, f, indent=2)
    
    @classmethod
    def pregenerate_key_pool(cls, user_id: str, count: int, min_len: int = 32, max_len: int = 512):
        """
        Pre-generate pool of true OTP keys
        
        Args:
            user_id: Identifier for the user
            count: Number of keys to generate
            min_len: Minimum key length
            max_len: Maximum key length
        """
        import base64
        
        with cls.lock:
            pool = cls._load_pool()
            if user_id not in pool:
                pool[user_id] = []
            
            for _ in range(count):
                length = random.randint(min_len, max_len)
                key = ShannonOTP.generate_key(length)
                pool[user_id].append({
                    'key': base64.b64encode(key).decode(),
                    'length': length,
                    'used': False
                })
            
            cls._save_pool(pool)
    
    @classmethod
    def get_key_from_pool(cls, user_id: str, required_length: int) -> Optional[bytes]:
        """
        Get an unused OTP key from pool (TRUE OTP)
        Key is marked as used after retrieval
        """
        import base64
        
        with cls.lock:
            pool = cls._load_pool()
            if user_id not in pool:
                return None
            
            # Find key with matching or longer length
            for key_entry in pool[user_id]:
                if not key_entry['used'] and key_entry['length'] >= required_length:
                    key_entry['used'] = True
                    cls._save_pool(pool)
                    return base64.b64decode(key_entry['key'])[:required_length]
            
            return None
    
    @classmethod
    def derive_key(cls, shared_secret: str, length: int, nonce: int = 0) -> bytes:
        """
        Derive key from shared secret (NOT true OTP, but practical)
        
        WARNING: This reduces security to stream cipher level!
        For TRUE OTP, use get_key_from_pool() instead.
        
        Uses HKDF-like construction:
        key = HMAC-SHA256(secret, nonce || counter) || HMAC-SHA256(secret, nonce || counter+1) || ...
        """
        import hmac
        
        key = b''
        counter = 0
        while len(key) < length:
            # HKDF-Expand style
            info = f"{nonce}:{counter}".encode()
            block = hmac.new(
                shared_secret.encode(),
                info,
                hashlib.sha256
            ).digest()
            key += block
            counter += 1
        
        return key[:length]


# ==============================================================================
# LAYER 5: MESSAGE STORE
# ==============================================================================
class MessageStore:
    """
    Thread-safe message storage untuk queueing messages antar node
    """
    
    STORE_FILE = "covert_messages.json"
    lock = threading.Lock()
    
    @classmethod
    def _load(cls) -> dict:
        if not os.path.exists(cls.STORE_FILE):
            return {}
        try:
            with open(cls.STORE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    
    @classmethod
    def _save(cls, data: dict):
        with open(cls.STORE_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    
    @classmethod
    def store(cls, target_id: str, sender_id: str, message: str, encrypted: bool = True):
        """Store message for target user"""
        with cls.lock:
            data = cls._load()
            if target_id not in data:
                data[target_id] = []
            data[target_id].append({
                'sender': sender_id,
                'message': message,
                'encrypted': encrypted,
                'timestamp': time.time()
            })
            cls._save(data)
    
    @classmethod
    def retrieve(cls, user_id: str) -> Optional[dict]:
        """Retrieve first message for user (FIFO)"""
        with cls.lock:
            data = cls._load()
            if user_id in data and len(data[user_id]) > 0:
                msg = data[user_id].pop(0)
                cls._save(data)
                return msg
            return None
    
    @classmethod
    def peek(cls, user_id: str) -> int:
        """Check how many messages are queued"""
        with cls.lock:
            data = cls._load()
            return len(data.get(user_id, []))


# ==============================================================================
# UTILITY: Import time (placed here to avoid circular imports)
# ==============================================================================
import time
import random
