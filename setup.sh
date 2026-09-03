#!/bin/bash
set -e

echo "=== Installing dependencies for Bitcoin Puzzle 71 C++ Solver ==="
if [ -f /etc/debian_version ]; then
    sudo apt-get update
    sudo apt-get install -y build-essential g++ make libsecp256k1-dev libssl-dev libcurl4-openssl-dev
elif [ -f /etc/arch-release ]; then
    sudo pacman -Sy --noconfirm base-devel libsecp256k1 openssl curl
elif [ -f /etc/fedora-release ]; then
    sudo dnf install -y gcc-c++ make libsecp256k1-devel openssl-devel libcurl-devel
else
    echo "[!] Please install g++, make, libsecp256k1, libssl, and libcurl manually."
fi

echo "=== Compiling puzzle71_solver ==="
make clean || true
make
chmod +x puzzle71_solver 2>/dev/null || true

echo "=== Setup complete! Run with: ==="
echo "./puzzle71_solver --puzzle 71 --user lucky --workers max"
