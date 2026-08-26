┌─────────────────────────────────────────────────────────────────────────────┐
│                    COVERT TRANSPORT PROTOCOL STACK                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐                                                            │
│  │  PLAINTEXT  │  "UserB|UserA|Hello World"                                │
│  └──────┬──────┘                                                            │
│         │                                                                    │
│         ▼ (1) SHANNON ONE-TIME PAD                                          │
│  ┌─────────────┐                                                            │
│  │ CIPHERTEXT  │  Random bytes, P(0)=P(1)=0.5, Zero Entropy Anomaly        │
│  │ (Perfect    │  C_i = P_i ⊕ K_i                                          │
│  │  Secrecy)   │  P(M=m|C=c) = P(M=m)  [Shannon 1949]                      │
│  └──────┬──────┘                                                            │
│         │                                                                    │
│         ▼ (2) HAMMING(7,4) ENCODING OVER GF(2)                             │
│  ┌─────────────┐                                                            │
│  │ ERROR       │  4 bits → 7 bits codeword                                 │
│  │ PROTECTED   │  v = d · G (mod 2)                                         │
│  │             │  Can correct 1-bit errors via syndrome calculation         │
│  └──────┬──────┘                                                            │
│         │                                                                    │
│         ▼ (3) INTERLEAVING (DEPTH=7)                                        │
│  ┌─────────────┐                                                            │
│  │ BURST       │  Spreads bits across multiple Hamming blocks              │
│  │ RESISTANT   │  Burst errors → Isolated single-bit errors               │
│  └──────┬──────┘                                                            │
│         │                                                                    │
│         ▼ (4) ICMPv6 ENCAPSULATION                                          │
│  ┌─────────────────────────────────────────────────────────────────┐       │
│  │                     ICMPv6 PACKET                               │       │
│  ├─────────────────────────────────────────────────────────────────┤       │
│  │  OUTBOUND: Echo Request (Type 128)                              │       │
│  │  INBOUND:  Port Unreachable (Type 1, Code 4)                    │       │
│  │                                                                 │       │
│  │  Looks like: Standard network error to DPI/routers             │       │
│  │  Reality:   Covert C2 channel with encrypted payload           │       │
│  └─────────────────────────────────────────────────────────────────┘       │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  SECURITY PROPERTIES:                                                        │
│  • Information-Theoretic Security (OTP) - Unbreakable even by quantum      │
│  • Self-Healing Data (Hamming + Interleave) - No retransmission needed     │
│  • Zero C2 Signature (Port Unreachable) - Appears as network errors        │
│  • Anti-Beaconing (Jittered polling 3.5-8.2s) - No periodic patterns       │
└─────────────────────────────────────────────────────────────────────────────┘
