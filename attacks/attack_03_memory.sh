#!/bin/bash

# Security Test 03: Memory Remanence (Cold Boot / RAM Dump Attack)
# Objective: Verify that sensitive data (passwords) is scrubbed from RAM
#            and cannot be retrieved via memory dumping tools.

# ANSI Color Codes for Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- 1. CONFIGURATION & PATH RESOLUTION ---

# Automatically locate the release binary
if [ -f "../target/release/rust_pass" ]; then
    BIN="../target/release/rust_pass"
elif [ -f "./target/release/rust_pass" ]; then
    BIN="./target/release/rust_pass"
else
    echo -e "${RED}[ERROR] Binary not found.${NC}"
    echo "Please run 'cargo build --release' first."
    exit 1
fi

# Define dump file location (Absolute path to avoid gcore issues)
DUMP_NAME="memory_dump"
DUMP_PATH="$(pwd)/$DUMP_NAME"

# The "Canary" secret we will inject and search for
CANARY="SECRET_KEY_IN_RAM_12345"

echo -e "${BLUE}====================================================${NC}"
echo -e "${YELLOW}   SECURITY TEST 03: MEMORY DUMPING (RAM)            ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "Objective: Extract secrets from process memory before they are scrubbed."

# --- 2. ENVIRONMENT CLEANUP ---

# Kill any previous instances to ensure a clean state
pkill -f rust_pass > /dev/null 2>&1
# Remove previous dump files
rm -f "${DUMP_PATH}"*
# Remove existing vault to trigger "New Vault" creation flow
rm -f "$HOME/.passrust/vault.json"

# --- 3. ATTACK SIMULATION ---

echo -e "1. [SETUP] Launching PassRust in background..."
echo -e "   Injecting Canary Secret: '${YELLOW}$CANARY${NC}'"

# Launch the binary in background mode (&).
# We pipe the password twice because a new vault asks for confirmation.
# The Rust code must have a sleep() delay to keep the process alive for dumping.
printf "$CANARY\n$CANARY\n" | $BIN --test-memory-dump add bank.com user 123 > /dev/null 2>&1 &
PID=$!

echo -e "   Target Process ID (PID): $PID"
echo -e "   Waiting for secret to be loaded into RAM..."
sleep 2 # Allow time for Rust to initialize and allocate memory variables

# Validation: Ensure the process didn't crash or exit too early
if ! ps -p $PID > /dev/null; then
    echo -e "${RED}[ERROR] Process died unexpectedly.${NC}"
    echo "       Make sure you added the 'thread::sleep' in your Rust main.rs"
    exit 1
fi

echo -e "\n2. [ATTACK] Dumping process memory to disk..."
# 'gcore' dumps the full process memory map without killing it.
# Requires sudo because we are accessing protected memory space.
if sudo gcore -o "$DUMP_PATH" $PID > /dev/null 2>&1; then
    echo -e "   Memory dump successful."
else
    echo -e "${RED}[ERROR] 'gcore' failed execution.${NC}"
    echo "       Ensure GDB is installed (sudo apt install gdb)."
    kill $PID
    exit 1
fi

# Terminate the target process (cleanup)
kill $PID > /dev/null 2>&1

# --- 4. FORENSIC ANALYSIS ---

# Find the actual file generated (gcore appends the PID to the filename)
GENERATED_FILE=$(ls "${DUMP_PATH}"* 2>/dev/null | head -n 1)
echo -e "\n3. [ANALYSIS] Scanning binary dump for plaintext strings..."

# 'strings' extracts printable characters from binary files.
# 'grep' searches for our canary password.
if strings "$GENERATED_FILE" | grep -q "$CANARY"; then
    echo -e "\n${RED}[FAIL] VULNERABILITY CONFIRMED!${NC}"
    echo -e "       The secret '${YELLOW}$CANARY${NC}' was found in plain text in RAM."
    echo -e "       Cause: Memory was not zeroized or std::io buffer leaked the input."
else
    echo -e "\n${GREEN}[PASS] SECURE!${NC}"
    echo -e "       The secret was NOT found in the memory dump."
    echo -e "       Defense: Zeroize + Raw I/O successfully scrubbed the data."
fi

# Final Cleanup
rm -f "${DUMP_PATH}"*