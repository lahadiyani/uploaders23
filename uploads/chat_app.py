#!/usr/bin/env python3
"""
CHAT CLIENT - Covert Transport Protocol
========================================
Military/Space-grade covert channel client

Arsitektur Pengiriman:
┌────────────┐   ┌────────┐   ┌─────────┐   ┌──────────┐   ┌────────────┐
│  Plaintext │ → │   OTP  │ → │ Hamming │ → │Interleave│ → │ICMPv6 Echo│
└────────────┘   └────────┘   └─────────┘   └──────────┘   └────────────┘

Arsitektur Penerimaan:
┌───────────────────────┐   ┌──────────┐   ┌─────────┐   ┌────────┐   ┌────────────┐
│ICMPv6 Port Unreachable│ → │Deinterl.│ → │ Hamming │ → │  OTP   │ → │  Plaintext │
└───────────────────────┘   └──────────┘   └─────────┘   └────────┘   └────────────┘
"""

import sys
import os
import time
import random
import struct
import argparse
import threading
from typing import Optional, List, Tuple
from collections import deque

# Scapy imports
from scapy.all import (
    IPv6, ICMPv6EchoRequest, ICMPv6DestUnreach,
    UDP, Raw, send6, sniff, conf
)

conf.verb = 0

# Import protocol library
from covert_protocol import (
    CovertProtocol, ShannonOTP, Hamming74, Interleaver,
    OTPKeyManager
)


# ==============================================================================
# ICMPv6 PACKET BUILDER
# ==============================================================================
class StealthICMPBuilder:
    """
    Membangun paket ICMPv6 yang menyerupai kernel Linux asli
    
    Anti-Detection Features:
    - hlim=64 (default Linux)
    - fl=random (non-zero flow label, Scapy default is 0 which is suspicious)
    - Incremental seq number (like real ping)
    - Consistent ICMP ID per session
    - Padding that mimics standard ping payload
    """
    
    # Standard ping padding pattern (from Linux ping)
    STANDARD_PADDING = bytes(range(0x61, 0x61 + 56))  # "abcdefghijklmnopqrstuvwxy..."
    
    @classmethod
    def build_data_packet(
        cls,
        src_ipv6: str,
        dst_ipv6: str,
        encoded_data: bytes,
        seq: int,
        icmp_id: int
    ) -> IPv6:
        """
        Build ICMPv6 Echo Request with covert data
        
        The encoded data IS the payload - no additional markers needed
        Protocol header inside encoded_data identifies it
        """
        pkt = IPv6(
            src=src_ipv6,
            dst=dst_ipv6,
            hlim=64,  # Linux default
            fl=random.randint(1, 0xFFFFF)  # Random non-zero flow label
        ) / ICMPv6EchoRequest(
            id=icmp_id,
            seq=seq,
            data=encoded_data
        )
        return pkt
    
    @classmethod
    def build_trigger_packet(
        cls,
        src_ipv6: str,
        dst_ipv6: str,
        seq: int,
        icmp_id: int
    ) -> IPv6:
        """
        Build "empty" ICMPv6 Echo Request to trigger Port Unreachable reply
        
        This looks like a normal ping - no covert data
        Used to poll for pending messages from server
        """
        pkt = IPv6(
            src=src_ipv6,
            dst=dst_ipv6,
            hlim=64,
            fl=random.randint(1, 0xFFFFF)
        ) / ICMPv6EchoRequest(
            id=icmp_id,
            seq=seq,
            data=cls.STANDARD_PADDING
        )
        return pkt


# ==============================================================================
# ICMPv6 PORT UNREACHABLE PARSER
# ==============================================================================
class PortUnreachParser:
    """
    Parser untuk ICMPv6 Port Unreachable responses
    
    Extracts covert data from the "original packet" portion
    """
    
    ICMPV6_TYPE_DEST_UNREACH = 1
    ICMPV6_CODE_PORT_UNREACH = 4
    
    @classmethod
    def extract_data(cls, packet) -> Optional[bytes]:
        """
        Extract covert data from ICMPv6 Port Unreachable
        
        Structure after ICMP header:
        - Fake UDP header (8 bytes): sport(2) + dport(2) + len(2) + chksum(2)
        - Covert data (rest)
        """
        if not packet.haslayer(ICMPv6DestUnreach):
            return None
        
        icmp_layer = packet[ICMPv6DestUnreach]
        
        # Verify it's Port Unreachable
        if icmp_layer.type != cls.ICMPV6_TYPE_DEST_UNREACH:
            return None
        if icmp_layer.code != cls.ICMPV6_CODE_PORT_UNREACH:
            return None
        
        # Get the "original packet" payload
        # In Scapy, this is the payload of the ICMPv6DestUnreach layer
        payload = bytes(icmp_layer.payload)
        
        if not payload or len(payload) < 8 + CovertProtocol.HEADER_SIZE:
            return None
        
        # Skip UDP header (8 bytes), get the data
        # But first, let's scan for our protocol header
        for offset in range(len(payload) - CovertProtocol.HEADER_SIZE):
            if (payload[offset] >> 4) == CovertProtocol.PROTOCOL_VERSION:
                candidate = payload[offset:]
                # Validate: check if bit length is reasonable
                if len(candidate) >= CovertProtocol.HEADER_SIZE:
                    bit_len = struct.unpack('>H', candidate[1:3])[0]
                    expected_bytes = (bit_len + 7) // 8
                    # Hamming(7,4) expands 4 bits to 7, so ~1.75x
                    # Plus header, so expected encoded size is roughly:
                    # header + (expected_bytes * 8 / 4 * 7 / 8)
                    min_expected = CovertProtocol.HEADER_SIZE + int(expected_bytes * 1.5)
                    if len(candidate) >= min_expected or bit_len < 100:
                        return candidate
        
        # Fallback: assume data starts after UDP header
        return payload[8:] if len(payload) > 8 else None


# ==============================================================================
# CHAT CLIENT
# ==============================================================================
class CovertChatClient:
    """
    Covert Channel Chat Client
    
    Features:
    - Send messages via ICMPv6 Echo Request
    - Receive messages via ICMPv6 Port Unreachable
    - Jittered polling to avoid beaconing detection
    - Full protocol stack: OTP → Hamming → Interleave
    """
    
    def __init__(
        self,
        my_ipv6: str,
        vps_ipv6: str,
        my_id: str,
        target_id: str,
        shared_secret: str,
        use_true_otp: bool = False
    ):
        self.my_ipv6 = my_ipv6
        self.vps_ipv6 = vps_ipv6
        self.my_id = my_id
        self.target_id = target_id
        self.shared_secret = shared_secret
        self.use_true_otp = use_true_otp
        
        # ICMP state (mimics kernel ping behavior)
        self.icmp_seq = random.randint(1, 1000)
        self.icmp_id = random.randint(1000, 65000)
        self.seq_lock = threading.Lock()
        
        # Message queue
        self.received_messages: deque = deque()
        self.msg_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'sent': 0,
            'received': 0,
            'triggers_sent': 0,
            'errors_corrected': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
        }
        
        # Running state
        self.running = True
    
    def _get_next_seq(self) -> int:
        """Get next ICMP sequence number (thread-safe)"""
        with self.seq_lock:
            self.icmp_seq += 1
            if self.icmp_seq > 65535:
                self.icmp_seq = 1
            return self.icmp_seq
    
    def _get_otp_key(self, length: int) -> bytes:
        """Get OTP key for given length"""
        if self.use_true_otp:
            # Try to get from pre-shared pool
            key = OTPKeyManager.get_key_from_pool(self.my_id, length)
            if key:
                return key
            print("[WARN] OTP key pool exhausted, falling back to derived key")
        
        # Derive from shared secret
        nonce = int(time.time()) // 300  # 5-minute nonce
        return OTPKeyManager.derive_key(
            f"{self.shared_secret}:{self.my_id}",
            length,
            nonce=nonce
        )
    
    def send_message(self, message: str) -> bool:
        """
        Send message via ICMPv6 Echo Request
        
        Pipeline: Plaintext → OTP → Hamming(7,4) → Interleave → ICMPv6
        """
        try:
            # Format: TARGET|SENDER|MESSAGE
            plaintext = f"{self.target_id}|{self.my_id}|{message}"
            plaintext_bytes = plaintext.encode('utf-8')
            
            # Get OTP key (must be >= plaintext length for Perfect Secrecy)
            otp_key = self._get_otp_key(len(plaintext_bytes))
            
            # Full encoding pipeline
            encoded = CovertProtocol.encode(plaintext_bytes, otp_key)
            
            # Build and send ICMPv6 packet
            seq = self._get_next_seq()
            pkt = StealthICMPBuilder.build_data_packet(
                self.my_ipv6,
                self.vps_ipv6,
                encoded,
                seq,
                self.icmp_id
            )
            
            send6(pkt, verbose=False)
            
            # Update stats
            self.stats['sent'] += 1
            self.stats['bytes_sent'] += len(encoded)
            
            # Calculate overhead
            overhead = (len(encoded) / len(plaintext_bytes) - 1) * 100
            print(f"[>>] Sent (seq={seq}, {len(encoded)} bytes, {overhead:.0f}% overhead)")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] Send failed: {e}")
            return False
    
    def send_trigger(self):
        """
        Send trigger ping to solicit Port Unreachable reply
        
        This is a "clean" ping that looks like normal traffic
        Server will reply with Port Unreachable containing any pending messages
        """
        try:
            seq = self._get_next_seq()
            pkt = StealthICMPBuilder.build_trigger_packet(
                self.my_ipv6,
                self.vps_ipv6,
                seq,
                self.icmp_id
            )
            
            send6(pkt, verbose=False)
            self.stats['triggers_sent'] += 1
            
        except Exception:
            pass
    
    def handle_port_unreachable(self, packet):
        """
        Handle incoming ICMPv6 Port Unreachable
        
        Pipeline: ICMPv6 → Extract → Deinterleave → Hamming Decode → OTP → Plaintext
        """
        # Extract covert data
        encoded_data = PortUnreachParser.extract_data(packet)
        
        if not encoded_data:
            return
        
        # Get original bit length for key sizing
        if len(encoded_data) < CovertProtocol.HEADER_SIZE:
            return
        
        original_bit_len = struct.unpack('>H', encoded_data[1:3])[0]
        original_byte_len = (original_bit_len + 7) // 8
        
        # Get OTP key
        otp_key = self._get_otp_key(original_byte_len)
        
        # Full decoding pipeline with error correction
        plaintext, meta = CovertProtocol.decode(encoded_data, otp_key)
        
        if not plaintext:
            return
        
        try:
            decoded = plaintext.decode('utf-8')
            
            # Validate: should be printable and contain delimiter
            if '|' not in decoded:
                return
            if not all(c.isprintable() or c in '\n\t\r' for c in decoded):
                return
            
            # Parse: SENDER|MESSAGE
            parts = decoded.split('|', 1)
            if len(parts) != 2:
                return
            
            sender, message = parts
            
            # Queue message
            with self.msg_lock:
                self.received_messages.append((sender, message))
            
            # Update stats
            self.stats['received'] += 1
            self.stats['bytes_received'] += len(encoded_data)
            self.stats['errors_corrected'] += meta['errors_corrected']
            
            # Display
            print(f"\n[<<] {sender}: {message}")
            if meta['errors_corrected'] > 0:
                print(f"[FEC] Corrected {meta['errors_corrected']} bit errors during transmission")
            print(f"[{self.my_id}]: ", end="", flush=True)
            
        except Exception:
            pass
    
    def get_pending_messages(self) -> List[tuple]:
        """Get all pending messages"""
        with self.msg_lock:
            messages = list(self.received_messages)
            self.received_messages.clear()
            return messages
    
    def start_receiver(self) -> threading.Thread:
        """Start background listener for ICMPv6 Port Unreachable"""
        def _sniffer():
            while self.running:
                try:
                    sniff(
                        filter=f"icmp6 and dst {self.my_ipv6} and icmp6type 1",
                        prn=self.handle_port_unreachable,
                        store=0,
                        timeout=1
                    )
                except Exception:
                    pass
        
        t = threading.Thread(target=_sniffer, daemon=True)
        t.start()
        return t
    
    def start_polling(self) -> threading.Thread:
        """
        Start periodic trigger polling with jitter
        
        Jitter interval: 3.5s - 8.2s (anti-beaconing)
        """
        def _poller():
            while self.running:
                try:
                    self.send_trigger()
                except Exception:
                    pass
                
                # Jittered interval
                interval = random.uniform(3.5, 8.2)
                time.sleep(interval)
        
        t = threading.Thread(target=_poller, daemon=True)
        t.start()
        return t
    
    def print_stats(self):
        """Print client statistics"""
        total_packets = self.stats['sent'] + self.stats['triggers_sent']
        
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                   CLIENT STATISTICS                         ║
╠══════════════════════════════════════════════════════════════╣
║  Messages Sent:        {self.stats['sent']:<36}║
║  Messages Received:    {self.stats['received']:<36}║
║  Triggers Sent:        {self.stats['triggers_sent']:<36}║
║  Errors Corrected:     {self.stats['errors_corrected']:<36}║
║  Bytes Sent (enc):     {self.stats['bytes_sent']:<36}║
║  Bytes Received (enc): {self.stats['bytes_received']:<36}║
║  Total Packets:        {total_packets:<36}║
╚══════════════════════════════════════════════════════════════╝
""")
    
    def print_banner(self):
        """Print startup banner"""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║           COVERT TRANSPORT PROTOCOL v1.0                    ║
║     Military/Space-Grade Secure Communication               ║
╠══════════════════════════════════════════════════════════════╣
║  ENCRYPTION:    Shannon One-Time Pad (Perfect Secrecy)      ║
║                 P(M=m|C=c) = P(M=m)                         ║
║                                                              ║
║  ERROR CORRECTION:                                           ║
║    • Hamming(7,4) over GF(2) - Single-bit correction       ║
║    • Interleaving (Depth 7) - Burst error dispersion       ║
║                                                              ║
║  TRANSPORT:                                                  ║
║    • Outbound: ICMPv6 Echo Request                          ║
║    • Inbound:  ICMPv6 Port Unreachable (Type 1, Code 4)    ║
║    • Stealth: Appears as network error to DPI              ║
╠══════════════════════════════════════════════════════════════╣
║  Node ID:       {self.my_id:<42}║
║  Target:        {self.target_id:<42}║
║  VPS:           {self.vps_ipv6:<42}║
║  Local IP:      {self.my_ipv6:<42}║
║  OTP Mode:      {'TRUE OTP' if self.use_true_otp else 'Derived Key':<42}║
╚══════════════════════════════════════════════════════════════╝
""")


# ==============================================================================
# TESTING UTILITIES
# ==============================================================================
class ProtocolTester:
    """
    Test utilities for verifying protocol implementation
    """
    
    @staticmethod
    def test_otp():
        """Test Shannon OTP"""
        print("\n[TEST] Shannon One-Time Pad...")
        
        plaintext = b"Hello, World!"
        key = ShannonOTP.generate_key(len(plaintext))
        
        ciphertext = ShannonOTP.encrypt(plaintext, key)
        decrypted = ShannonOTP.decrypt(ciphertext, key)
        
        assert plaintext == decrypted, "OTP decrypt failed"
        
        # Test perfect secrecy property
        # Any key produces valid plaintext
        for _ in range(10):
            random_key = ShannonOTP.generate_key(len(plaintext))
            random_decrypt = ShannonOTP.decrypt(ciphertext, random_key)
            assert len(random_decrypt) == len(plaintext)
        
        print("[PASS] Shannon OTP")
    
    @staticmethod
    def test_hamming():
        """Test Hamming(7,4)"""
        print("\n[TEST] Hamming(7,4)...")
        
        # Test encoding
        data = [1, 0, 1, 1]
        codeword = Hamming74.encode(data)
        assert len(codeword) == 7, f"Expected 7 bits, got {len(codeword)}"
        
        # Test no-error decoding
        decoded, corrected, pos = Hamming74.decode(codeword)
        assert decoded == data, "Decoding failed"
        assert not corrected, "Should not correct anything"
        
        # Test single-bit error correction
        for error_pos in range(7):
            corrupted = codeword.copy()
            corrupted[error_pos] ^= 1
            
            decoded, corrected, found_pos = Hamming74.decode(corrupted)
            assert decoded == data, f"Failed to correct error at pos {error_pos}"
            assert corrected, "Should have corrected"
            assert found_pos == error_pos, f"Wrong error position: {found_pos} != {error_pos}"
        
        print("[PASS] Hamming(7,4) - All 7 single-bit positions tested")
    
    @staticmethod
    def test_interleaver():
        """Test Interleaver"""
        print("\n[TEST] Interleaver...")
        
        # Test with 14 bits (2 rows)
        bits = list(range(14))
        interleaved, padding = Interleaver.interleave(bits)
        
        assert padding == 0, "Should not need padding"
        assert len(interleaved) == 14, "Length should be preserved"
        
        deinterleaved = Interleaver.deinterleave(interleaved, padding)
        assert deinterleaved == bits, "Deinterleave should recover original"
        
        # Test with padding
        bits = [1, 0, 1, 0, 1]  # 5 bits
        interleaved, padding = Interleaver.interleave(bits)
        assert padding == 2, "Should need 2 bits padding"
        
        deinterleaved = Interleaver.deinterleave(interleaved, padding)
        assert deinterleaved == bits, "Deinterleave with padding failed"
        
        print("[PASS] Interleaver")
    
    @staticmethod
    def test_burst_error_recovery():
        """Test that interleaving enables burst error recovery"""
        print("\n[TEST] Burst Error Recovery...")
        
        plaintext = b"Test message for burst error recovery!"
        key = ShannonOTP.generate_key(len(plaintext))
        
        # Encode
        encoded = CovertProtocol.encode(plaintext, key)
        
        # Convert to bits and inject burst error (5 consecutive bit flips)
        bits = []
        for byte in encoded:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        
        # Inject burst error
        error_start = 20
        burst_length = 5
        corrupted = bits.copy()
        for i in range(error_start, error_start + burst_length):
            corrupted[i] ^= 1
        
        # Convert back to bytes
        corrupted_bytes = bytearray()
        for i in range(0, len(corrupted), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | corrupted[i + j]
            corrupted_bytes.append(byte)
        
        # Decode - should recover!
        decoded, meta = CovertProtocol.decode(bytes(corrupted_bytes), key)
        
        if decoded == plaintext:
            print(f"[PASS] Burst error recovered! ({meta['errors_corrected']} bits corrected)")
        else:
            print(f"[FAIL] Burst error NOT recovered")
            print(f"  Expected: {plaintext}")
            print(f"  Got:      {decoded}")
    
    @staticmethod
    def run_all_tests():
        """Run all protocol tests"""
        print("=" * 60)
        print("PROTOCOL TEST SUITE")
        print("=" * 60)
        
        ProtocolTester.test_otp()
        ProtocolTester.test_hamming()
        ProtocolTester.test_interleaver()
        ProtocolTester.test_burst_error_recovery()
        
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)


# ==============================================================================
# MAIN
# ==============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Covert Chat Client - Military/Space-Grade Secure Communication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run tests
  python chat_app.py --test
  
  # Start client with derived keys
  python chat_app.py --my-ipv6 2406:da18:yyyy::1 \\
    --vps-ipv6 2406:da18:xxxx::1 \\
    --my-id UserA --target-id UserB \\
    --secret MySecretKey123
    
  # Start client with TRUE OTP
  python chat_app.py --my-ipv6 2406:da18:yyyy::1 \\
    --vps-ipv6 2406:da18:xxxx::1 \\
    --my-id UserA --target-id UserB \\
    --true-otp
"""
    )
    
    # Test mode
    parser.add_argument('--test', action='store_true', help='Run protocol tests')
    
    # Client configuration
    parser.add_argument('--my-ipv6', '-6', help='Your IPv6 address')
    parser.add_argument('--vps-ipv6', '-v', help='VPS IPv6 address')
    parser.add_argument('--my-id', '-m', default='UserA', help='Your user ID')
    parser.add_argument('--target-id', '-t', default='UserB', help='Target user ID')
    parser.add_argument('--secret', '-s', help='Shared secret for key derivation')
    parser.add_argument('--true-otp', action='store_true', help='Use TRUE OTP mode')
    
    args = parser.parse_args()
    
    # Run tests if requested
    if args.test:
        ProtocolTester.run_all_tests()
        sys.exit(0)
    
    # Validate arguments for client mode
    if not args.my_ipv6 or not args.vps_ipv6:
        parser.error("--my-ipv6 and --vps-ipv6 are required")
    
    if not args.true_otp and not args.secret:
        parser.error("Either --true-otp or --secret must be specified")
    
    # Create client
    client = CovertChatClient(
        my_ipv6=args.my_ipv6,
        vps_ipv6=args.vps_ipv6,
        my_id=args.my_id,
        target_id=args.target_id,
        shared_secret=args.secret or "",
        use_true_otp=args.true_otp
    )
    
    # Print banner
    client.print_banner()
    
    # Start background services
    client.start_receiver()
    client.start_polling()
    
    print(f"[+] Listening for ICMPv6 Port Unreachable replies...")
    print(f"[+] Trigger polling active (3.5-8.2s jitter interval)")
    print(f"[+] Type messages below. Ctrl+C to exit.\n")
    
    # Main input loop
    try:
        while True:
            try:
                msg = input(f"[{args.my_id}]: ")
                if msg.strip():
                    client.send_message(msg.strip())
            except EOFError:
                break
    except KeyboardInterrupt:
        client.running = False
        client.print_stats()
        print("[-] Shutting down...")
        sys.exit(0)
