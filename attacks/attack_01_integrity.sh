#!/bin/bash

# Security Test 01: Integrity & Tampering
# Target: AES-256-GCM Authentication Tag

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Path configuration
VAULT_PATH="$HOME/.passrust/vault.json"
BACKUP_PATH="$HOME/.passrust/vault.json.bak"

echo -e "${BLUE}====================================================${NC}"
echo -e "${YELLOW}   SECURITY TEST 01: DATA INTEGRITY (BIT-FLIPPING)   ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "Objective: Verify that AES-GCM detects unauthorized file modifications.\n"

# 0. Pre-check
if [ ! -f "$VAULT_PATH" ]; then
    echo -e "${RED}[ERROR] Vault not found at $VAULT_PATH${NC}"
    echo "Please run 'passrust' to create a database first."
    exit 1
fi

# 1. Setup
echo -e "1. [SETUP] Creating a 'victim' credential entry..."
# Importante: Quitamos --quiet para evitar errores de argumentos en clap
cargo run --quiet -- add bank.com victim_user super_secret_123

# 2. Backup
echo -e "\n   [SETUP] Backing up the valid vault..."
cp "$VAULT_PATH" "$BACKUP_PATH"

# 3. Attack
echo -e "\n2. [ATTACK] Injecting corrupted bytes into the ciphertext..."
# Using sed to flip bits in the encrypted array
if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' 's/"ciphertext": \[/"ciphertext": \[255, /' "$VAULT_PATH"
else
    sed -i 's/"ciphertext": \[/"ciphertext": \[255, /' "$VAULT_PATH"
fi
echo -e "   ${RED}>> Malicious modification applied to disk.${NC}"

# 4. Verification
echo -e "\n3. [VERIFY] Attempting to decrypt the compromised entry..."
echo -e "   Running: passrust get bank.com"

# Capturamos fallo. Si falla (exit code != 0), es un éxito de seguridad.
if ! cargo run --quiet -- get bank.com; then
    echo -e "\n${GREEN}[PASS] SECURITY SUCCESS!${NC}"
    echo -e "       The system detected the tampering and refused to decrypt."
    echo -e "       Error: Auth Tag mismatch (Integrity Preserved)."
else
    echo -e "\n${RED}[FAIL] CRITICAL VULNERABILITY!${NC}"
    echo -e "       The system returned data despite the file being corrupted."
fi

# 5. Cleanup
echo -e "\n4. [CLEANUP] Restoring original database..."
mv "$BACKUP_PATH" "$VAULT_PATH"
echo -e "${BLUE}====================================================${NC}"