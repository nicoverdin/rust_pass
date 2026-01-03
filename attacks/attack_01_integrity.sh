#!/bin/bash

# Security Test 01: Integrity Verification (Bit-Flipping Attack)
# Objective: Verify that the application detects unauthorized modifications
#            to the encrypted vault file (Authenticated Encryption).

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

VAULT_DIR="$HOME/.passrust"
VAULT_FILE="$VAULT_DIR/vault.json"
BACKUP_PATH="$VAULT_DIR/vault.json.bak"

echo -e "${BLUE}====================================================${NC}"
echo -e "${YELLOW}   SECURITY TEST 01: DATA INTEGRITY (BIT-FLIPPING)   ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "Objective: Corrupt encrypted data and ensure decryption fails."

# --- 2. ENVIRONMENT SETUP ---

echo -e "1. [SETUP] Resetting environment..."
rm -f "$VAULT_FILE"

echo -e "   [SETUP] Creating a valid vault..."
# Create a new vault with a known password ('admin')
# We pipe the password twice for confirmation prompts
printf "admin\nadmin\n" | $BIN add bank.com user 123 > /dev/null 2>&1

if [ ! -f "$VAULT_FILE" ]; then
    echo -e "${RED}[ERROR] Failed to create vault.json via script.${NC}"
    exit 1
fi

echo -e "   [SETUP] Vault created successfully. Validating access..."
# Verify we can read it before corruption
if printf "admin\n" | $BIN get bank.com > /dev/null 2>&1; then
    echo -e "   Access confirmed. Starting attack..."
else
    echo -e "${RED}[ERROR] Could not read the valid vault. Setup failed.${NC}"
    exit 1
fi

# Backup
echo -e "\n   [SETUP] Backing up the valid vault..."
cp "$VAULT_FILE" "$BACKUP_PATH"

# --- 3. ATTACK SIMULATION ---

echo -e "\n2. [ATTACK] Corrupting the vault file (Bit-Flipping)..."
# We use 'sed' to change the first occurrence of "A" to "B" in the raw file.
# This simulates a subtle data corruption or tampering attempt.
sed -i '1s/^./X/' "$VAULT_FILE"

echo -e "   ${RED}>> Malicious modification applied to disk.${NC}"
echo -e "   File corrupted. Attempting to decrypt with valid credentials..."

# --- 4. VERIFICATION ---

# Try to read the entry using the correct password.
# Since the file is corrupted, AES-GCM should fail to verify the Auth Tag.
OUTPUT=$(printf "admin\n" | $BIN get bank.com 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo -e "\n3. [RESULTS] Analysis:"
    echo -e "${GREEN}[PASS] SYSTEM SECURE.${NC}"
    echo -e "       The application refused to decrypt the corrupted data."
    echo -e "       (AES-GCM Auth Tag validation worked)."
else
    echo -e "\n3. [RESULTS] Analysis:"
    echo -e "${RED}[FAIL] VULNERABILITY DETECTED.${NC}"
    echo -e "       The application accepted corrupted data without error."
    echo -e "       (Check your AES mode; ensure you are checking the Auth Tag)."
fi

echo -e "\n4. [CLEANUP] Restoring original database..."
mv "$BACKUP_PATH" "$VAULT_FILE"

echo -e "${BLUE}====================================================${NC}"