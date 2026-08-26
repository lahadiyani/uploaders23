#!/usr/bin/env python3
"""
VPS RELAY SERVER - Covert Transport Protocol
==============================================
Node relay yang bertindak sebagai "error generator" palsu

Arsitektur:
┌──────────────┐     ICMPv6 Echo Request      ┌──────────────┐
│   Client A   │ ─────────────────────────►   │              │
│  (Sender)    │ ◄─────────────────────────   │   VPS RELAY  │
└──────────────┘   ICMPv6 Port Unreachable    │   (Server)   │
                                               │              │
┌──────────────┐     ICMPv6 Echo Request      │              │
│   Client B   │ ─────────────────────────►   │              │
│  (Receiver)  │ ◄─────────────────────────   │              │
└──────────────┘   ICMPv6 Port Unreachable    └──────────────┘

STEALTH PROPERTIES:
- Balasan terlihat seperti "Port Unreachable" error standar Linux
- Tidak ada pola C2 yang terdeteksi DPI
- Data disisipkan di bagian "original packet" ICMP error
"""

import sys
import os
import time
import random
import struct
import argparse
import threading
from typing import Optional, Dict, List
from collections import defaultdict

# Scapy imports
from scapy.all import (
    sniff, IPv6, ICMPv6EchoRequest, ICMPv6DestUnreach,
    UDP, TCP, Raw, send6, conf
)

# Suppress Scapy warnings
conf.verb = 0

# Import protocol library
from covert_protocol import (
    CovertProtocol, ShannonOTP, OTPKeyManager, 
    MessageStore, Hamming74, Interleaver
)


# ==============================================================================
# ICMPv6 PORT UNREACHABLE BUILDER
# ==============================================================================
class ICMPv6PortUnreachBuilder:
    """
    Membangun paket ICMPv6 Destination Unreachable / Port Unreachable
    
    Format ICMPv6 Dest Unreachable (RFC 4443):
    ┌───────────────────────────────────────────────────────────┐
    │ Type (1) │ Code (4) │         Checksum (16)              │
    ├───────────────────────────────────────────────────────────┤
    │                   Unused (32 bits)                       │
    ├───────────────────────────────────────────────────────────┤
    │         As much of invoking packet as possible           │
    │         without the original IPv6 header                 │
    └───────────────────────────────────────────────────────────┘
    
    Kami menyisipkan data di bagian "invoking packet" dengan
    format yang menyerupai UDP packet normal
    """
    
    ICMPV6_TYPE = 1
    ICMPV6_CODE_PORT_UNREACH = 4
    
    @classmethod
    def build_reply(
        cls,
        src_ipv6: str,
        dst_ipv6: str,
        original_packet: IPv6,
        covert_data: bytes
    ) -> IPv6:
        """
        Membuat ICMPv6 Port Unreachable dengan data tersembunyi
        
        Stealth technique:
        - Menggunakan port random yang "masuk akal" (high src, low dst)
        - UDP header looks legitimate
        - Data tersembunyi di UDP payload
        - Keseluruhan terlihat seperti error response normal
        """
        # Generate realistic-looking UDP header
        fake_src_port = random.randint(32768, 65535)  # Ephemeral port
        fake_dst_port = random.choice([
            80, 443, 8080, 8443, 3306, 5432, 6379, 27017  # Common ports
        ])
        
        # Build fake "original UDP packet" that caused the error
        # This is what would normally be included in ICMP error
        fake_udp = UDP(
            sport=fake_src_port,
            dport=fake_dst_port,
            len=8 + len(covert_data),
            chksum=0  # Checksum often zeroed in ICMP errors
        ) / Raw(load=covert_data)
        
        # Build ICMPv6 Destination Unreachable
        icmp_error = ICMPv6DestUnreach(code=cls.ICMPV6_CODE_PORT_UNREACH)
        
        # Assemble full packet
        reply = IPv6(
            src=src_ipv6,
            dst=dst_ipv6,
            hlim=64,  # Standard Linux TTL
            fl=random.randint(1, 0xFFFFF)  # Random flow label
        ) / icmp_error / fake_udp
        
        return reply
    
    @classmethod
    def extract_covert_data(cls, packet) -> Optional[bytes]:
        """
        Ekstrak data tersembunyi dari ICMPv6 Echo Request
        
        Format payload: [Protocol Header (3 bytes)] [Encoded Data]
        """
        if not packet.haslayer(ICMPv6EchoRequest):
            return None
        
        # Get raw payload
        raw_payload = bytes(packet[ICMPv6EchoRequest].payload)
        
        if not raw_payload or len(raw_payload) < CovertProtocol.HEADER_SIZE:
            return None
        
        # Check for our protocol magic
        version = (raw_payload[0] >> 4) & 0x0F
        if version == CovertProtocol.PROTOCOL_VERSION:
            return raw_payload
        
        # Alternative: Look for protocol header anywhere in payload
        # (in case of padding before the data)
        for offset in range(len(raw_payload) - CovertProtocol.HEADER_SIZE):
            if (raw_payload[offset] >> 4) == CovertProtocol.PROTOCOL_VERSION:
                candidate = raw_payload[offset:]
                # Quick validation: check if bit length makes sense
                if len(candidate) >= CovertProtocol.HEADER_SIZE:
                    bit_len = struct.unpack('>H', candidate[1:3])[0]
                    if 0 < bit_len <= len(candidate) * 8:
                        return candidate
        
        return None


# ==============================================================================
# USER IDENTIFICATION
# ==============================================================================
class UserIdentifier:
    """
    Identifikasi user berdasarkan IPv6 source address
    Menggunakan mapping statis atau prefix-based identification
    """
    
    # Static mapping (can be loaded from config)
    USER_MAP: Dict[str, str] = {}
    
    @classmethod
    def register_user(cls, ipv6: str, user_id: str):
        cls.USER_MAP[ipv6] = user_id
        print(f"[AUTH] Registered {user_id} at {ipv6}")
    
    @classmethod
    def identify(cls, ipv6: str) -> Optional[str]:
        return cls.USER_MAP.get(ipv6)
    
    @classmethod
    def get_ipv6(cls, user_id: str) -> Optional[str]:
        for ipv6, uid in cls.USER_MAP.items():
            if uid == user_id:
                return ipv6
        return None


# ==============================================================================
# VPS RELAY SERVER
# ==============================================================================
class VPSRelayServer:
    """
    Main VPS Relay Server Implementation
    
    Flow:
    1. Receive ICMPv6 Echo Request with covert data
    2. Decode: Deinterleave → Hamming Decode → OTP Decrypt
    3. Parse message (TARGET|SENDER|MESSAGE)
    4. Store message for target
    5. When target polls, reply with ICMPv6 Port Unreachable
    """
    
    def __init__(
        self,
        vps_ipv6: str,
        use_key_pool: bool = False,
        shared_secret: str = None,
        key_pool_size: int = 100
    ):
        self.vps_ipv6 = vps_ipv6
        self.use_key_pool = use_key_pool
        self.shared_secret = shared_secret
        
        # Statistics
        self.stats = {
            'packets_received': 0,
            'packets_decoded': 0,
            'packets_failed': 0,
            'errors_corrected': 0,
            'replies_sent': 0,
        }
        
        # Pending replies queue (per destination IPv6)
        self.pending_replies: Dict[str, List[bytes]] = defaultdict(list)
        self.reply_lock = threading.Lock()
        
        # Pre-generate key pool if enabled
        if use_key_pool:
            print("[*] Pre-generating OTP key pool for TRUE OTP...")
            for user in ['UserA', 'UserB']:
                OTPKeyManager.pregenerate_key_pool(user, key_pool_size)
            print(f"[+] Generated {key_pool_size * 2} true OTP keys")
    
    def _get_otp_key(self, user_id: str, length: int) -> Optional[bytes]:
        """Get OTP key for user"""
        if self.use_key_pool:
            # TRUE OTP: Get from pre-shared pool
            key = OTPKeyManager.get_key_from_pool(user_id, length)
            if key:
                return key
            # Fallback to derivation if pool exhausted
            print(f"[WARN] Key pool exhausted for {user_id}, falling back to derivation")
        
        if self.shared_secret:
            # Practical: Derive from shared secret
            nonce = int(time.time()) // 300  # Change nonce every 5 minutes
            return OTPKeyManager.derive_key(
                f"{self.shared_secret}:{user_id}",
                length,
                nonce=nonce
            )
        
        return None
    
    def _try_decode_with_all_users(
        self,
        encoded_data: bytes
    ) -> Optional[tuple]:
        """
        Try to decode data with each known user's key
        Returns: (user_id, plaintext, metadata) or None
        """
        # Get original bit length from header
        if len(encoded_data) < CovertProtocol.HEADER_SIZE:
            return None
        
        original_bit_len = struct.unpack('>H', encoded_data[1:3])[0]
        original_byte_len = (original_bit_len + 7) // 8
        
        # Try each registered user
        for ipv6, user_id in UserIdentifier.USER_MAP.items():
            key = self._get_otp_key(user_id, original_byte_len)
            if not key:
                continue
            
            plaintext, meta = CovertProtocol.decode(encoded_data, key)
            
            if plaintext:
                try:
                    decoded = plaintext.decode('utf-8')
                    # Validate: should be printable and contain our delimiter
                    if '|' in decoded and all(
                        c.isprintable() or c in '\n\t\r' 
                        for c in decoded
                    ):
                        return (user_id, decoded, meta)
                except Exception:
                    continue
        
        return None
    
    def process_icmp_request(self, packet):
        """
        Process incoming ICMPv6 Echo Request
        """
        # Check if it's an ICMPv6 Echo Request
        if not packet.haslayer(IPv6) or not packet.haslayer(ICMPv6EchoRequest):
            return
        
        self.stats['packets_received'] += 1
        src_ipv6 = packet[IPv6].src
        
        # Extract covert data
        covert_data = ICMPv6PortUnreachBuilder.extract_covert_data(packet)
        
        if not covert_data:
            return
        
        # Try to decode
        result = self._try_decode_with_all_users(covert_data)
        
        if result is None:
            self.stats['packets_failed'] += 1
            return
        
        user_id, decoded, meta = result
        self.stats['packets_decoded'] += 1
        self.stats['errors_corrected'] += meta['errors_corrected']
        
        # Parse message format: TARGET_ID|SENDER_ID|MESSAGE
        parts = decoded.split('|', 2)
        if len(parts) != 3:
            self.stats['packets_failed'] += 1
            return
        
        target_id, sender_id, message = parts
        
        print(f"\n[RECV] {sender_id} → {target_id}: {message}")
        print(f"[FEC] Blocks: {meta['total_blocks']}, "
              f"Corrected: {meta['errors_corrected']}, "
              f"Uncorrectable: {meta['uncorrectable_errors']}")
        
        # Store message for target
        MessageStore.store(target_id, sender_id, message)
        
        # Check if we should send reply now
        self._check_and_queue_reply(src_ipv6, user_id)
    
    def _check_and_queue_reply(self, client_ipv6: str, user_id: str):
        """Check for pending messages and queue reply"""
        msg = MessageStore.retrieve(user_id)
        if msg:
            # Format reply: SENDER|MESSAGE
            reply_text = f"{msg['sender']}|{msg['message']}"
            reply_bytes = reply_text.encode('utf-8')
            
            # Get OTP key for encoding
            key = self._get_otp_key(user_id, len(reply_bytes))
            if key:
                # Encode with full protocol stack
                encoded = CovertProtocol.encode(reply_bytes, key)
                
                with self.reply_lock:
                    self.pending_replies[client_ipv6].append(encoded)
    
    def send_pending_replies(self, packet):
        """
        Send pending replies via ICMPv6 Port Unreachable
        Triggered by ANY ICMPv6 Echo Request from a client with pending data
        """
        if not packet.haslayer(IPv6):
            return
        
        src_ipv6 = packet[IPv6].src
        
        with self.reply_lock:
            if src_ipv6 in self.pending_replies and self.pending_replies[src_ipv6]:
                encoded_data = self.pending_replies[src_ipv6].pop(0)
            else:
                return
        
        # Build ICMPv6 Port Unreachable reply
        reply_pkt = ICMPv6PortUnreachBuilder.build_reply(
            self.vps_ipv6,
            src_ipv6,
            packet[IPv6],
            encoded_data
        )
        
        # Send with slight random delay (jitter) for stealth
        time.sleep(random.uniform(0.005, 0.05))
        send6(reply_pkt, verbose=False)
        
        self.stats['replies_sent'] += 1
        user_id = UserIdentifier.identify(src_ipv6) or src_ipv6
        print(f"[SEND] Reply to {user_id} via Port Unreachable ({len(encoded_data)} bytes)")
        print(f"[{user_id}]: ", end="", flush=True)
    
    def print_stats(self):
        """Print server statistics"""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    VPS RELAY STATISTICS                     ║
╠══════════════════════════════════════════════════════════════╣
║  Packets Received:     {self.stats['packets_received']:<36}║
║  Packets Decoded:      {self.stats['packets_decoded']:<36}║
║  Packets Failed:       {self.stats['packets_failed']:<36}║
║  Errors Corrected:     {self.stats['errors_corrected']:<36}║
║  Replies Sent:         {self.stats['replies_sent']:<36}║
║  Decoding Rate:        {(self.stats['packets_decoded']/max(1,self.stats['packets_received'])*100):.1f}%{' ' * 32}║
╚══════════════════════════════════════════════════════════════╝
""")
    
    def start(self):
        """Start the VPS relay server"""
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║           VPS RELAY - COVERT TRANSPORT PROTOCOL             ║
╠══════════════════════════════════════════════════════════════╣
║  IPv6 Address:     {self.vps_ipv6:<39}║
║  OTP Mode:         {'TRUE OTP (Key Pool)' if self.use_key_pool else 'Derived Key':<39}║
║  Protocol Stack:   OTP → Hamming(7,4) → Interleaving       ║
║  Response Type:    ICMPv6 Port Unreachable (Type 1, Code 4) ║
╠══════════════════════════════════════════════════════════════╣
║  Registered Users: {len(UserIdentifier.USER_MAP):<39}║
║  Pending Messages: {MessageStore.peek('UserA') + MessageStore.peek('UserB'):<39}║
╚══════════════════════════════════════════════════════════════╝
""")
        
        print("[+] Listening for ICMPv6 Echo Requests...")
        print("[+] Will reply with ICMPv6 Port Unreachable (looks like network error)")
        print("[+] Press Ctrl+C to stop\n")
        
        # Start packet sniffer
        def packet_handler(packet):
            self.process_icmp_request(packet)
            self.send_pending_replies(packet)
        
        try:
            sniff(
                filter="icmp6",
                prn=packet_handler,
                store=0
            )
        except KeyboardInterrupt:
            self.print_stats()
            print("[-] Server shutting down...")
            sys.exit(0)


# ==============================================================================
# MAIN
# ==============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="VPS Relay Server - Covert Transport Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # With TRUE OTP (requires pre-shared key pool)
  python vps_relay.py --ipv6 2406:da18:xxxx::1 --true-otp
  
  # With derived keys (practical, not true OTP)
  python vps_relay.py --ipv6 2406:da18:xxxx::1 --secret MySecretKey123
  
  # Register users
  python vps_relay.py --ipv6 2406:da18:xxxx::1 --secret MySecretKey123 \\
    --register-user UserA=2406:da18:yyyy::1 \\
    --register-user UserB=2406:da18:zzzz::1
"""
    )
    
    parser.add_argument(
        '--ipv6', '-6',
        required=True,
        help='VPS IPv6 address'
    )
    parser.add_argument(
        '--secret', '-s',
        help='Shared secret for key derivation (NOT true OTP)'
    )
    parser.add_argument(
        '--true-otp',
        action='store_true',
        help='Use TRUE OTP with pre-shared key pool'
    )
    parser.add_argument(
        '--key-pool-size',
        type=int,
        default=100,
        help='Number of keys to pre-generate for TRUE OTP (default: 100)'
    )
    parser.add_argument(
        '--register-user', '-r',
        action='append',
        help='Register user: format USERID=IPV6_ADDRESS'
    )
    
    args = parser.parse_args()
    
    # Register users if specified
    if args.register_user:
        for user_spec in args.register_user:
            if '=' in user_spec:
                user_id, ipv6 = user_spec.split('=', 1)
                UserIdentifier.register_user(ipv6.strip(), user_id.strip())
    
    # Validate arguments
    if not args.true_otp and not args.secret:
        parser.error("Either --true-otp or --secret must be specified")
    
    # Create and start server
    server = VPSRelayServer(
        vps_ipv6=args.ipv6,
        use_key_pool=args.true_otp,
        shared_secret=args.secret,
        key_pool_size=args.key_pool_size
    )
    
    server.start()
