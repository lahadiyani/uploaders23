#!/bin/bash
# Setup script for Covert Transport Protocol

echo "=============================================="
echo "Covert Transport Protocol - Setup"
echo "=============================================="

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is required"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "[+] Python version: $PYTHON_VERSION"

# Install dependencies
echo "[*] Installing dependencies..."
pip3 install scapy --quiet

# Verify Scapy
python3 -c "from scapy.all import *; print('[+] Scapy installed successfully')"

# Create key pool for TRUE OTP mode (optional)
read -p "Generate TRUE OTP key pool? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 -c "
from covert_protocol import OTPKeyManager
for user in ['UserA', 'UserB']:
    OTPKeyManager.pregenerate_key_pool(user, 200)
print('[+] Generated 400 OTP keys (200 per user)')
"
fi

# Run tests
echo ""
read -p "Run protocol tests? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    python3 chat_app.py --test
fi

echo ""
echo "=============================================="
echo "Setup complete!"
echo ""
echo "Usage:"
echo "  1. Start VPS relay:"
echo "     python3 vps_relay.py --ipv6 YOUR_VPS_IPV6 --secret YOUR_SECRET"
echo ""
echo "  2. Start client A:"
echo "     python3 chat_app.py --my-ipv6 CLIENT_A_IPV6 --vps-ipv6 VPS_IPV6 \\"
echo "       --my-id UserA --target-id UserB --secret YOUR_SECRET"
echo ""
echo "  3. Start client B:"
echo "     python3 chat_app.py --my-ipv6 CLIENT_B_IPV6 --vps-ipv6 VPS_IPV6 \\"
echo "       --my-id UserB --target-id UserA --secret YOUR_SECRET"
echo "=============================================="
