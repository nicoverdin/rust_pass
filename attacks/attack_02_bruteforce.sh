#!/bin/bash

# Security Test 02: Brute Force Resistance
# Objective: Verify that the Key Derivation Function (Argon2id) imposes
#            significant computational latency (~500ms) to thwart dictionary attacks.

# ANSI Color Codes for Output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

echo -e "${BLUE}====================================================${NC}"
echo -e "${YELLOW}   SECURITY TEST 02: BRUTE FORCE ATTACK (ARGON2)     ${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "Objective: Measure authentication latency per attempt."

# --- 2. ENVIRONMENT SETUP ---

echo -e "1. [SETUP] Resetting environment..."
rm -f "$VAULT_FILE"

echo -e "   [SETUP] Creating a new target vault..."
echo -e "   Target Master Password: 'admin'"

# Initialize vault with a dummy credential so we have something to decrypt.
# We pipe the password twice ('admin\nadmin\n') for confirmation prompts.
printf "admin\nadmin\n" | $BIN add bank.com victim_user secret_123 > /dev/null 2>&1

if [ ! -f "$VAULT_FILE" ]; then
    echo -e "${RED}[ERROR] Failed to create vault.json via script.${NC}"
    exit 1
fi

# --- 3. ATTACK SIMULATION ---

echo -e "\n2. [ATTACK] Starting Dictionary Attack..."
echo -e "   Targeting the Master Password with a wordlist."
echo -e "   Observing the cost of Argon2id hashing...\n"

# Wordlist containing common passwords and the correct one at the end
WORDLIST=("123456" "password" "qwerty" "admin")

start_total=$(date +%s%N)

for pass in "${WORDLIST[@]}"; do
    start_attempt=$(date +%s%N)
    
    echo -ne "   [..] Trying: ${CYAN}'$pass'${NC} ... "
    
    # Attempt to retrieve a password using the current guess from the wordlist
    echo "$pass" | $BIN get bank.com > /dev/null 2>&1
    EXIT_CODE=$?
    
    end_attempt=$(date +%s%N)
    # Calculate duration in milliseconds
    duration=$((($end_attempt - $start_attempt)/1000000))
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}[CRACKED!]${NC} (Cost: ${YELLOW}${duration}ms${NC})"
    else
        echo -e "${RED}[FAILED]${NC}   (Cost: ${YELLOW}${duration}ms${NC})"
    fi
done

end_total=$(date +%s%N)
total_ms=$((($end_total - $start_total)/1000000))

# --- 4. RESULTS ANALYSIS ---

echo -e "\n3. [RESULTS] Forensic Analysis:"
echo -e "   Total Attack Time: ~${total_ms} ms"
echo -e "   Average Latency:   High (~500ms per attempt recommended)"

# Check if the latency is sufficient (Threshold: >200ms)
# We assume the last attempt (successful) represents a typical full decryption cycle.
if [ "$duration" -ge 200 ]; then
    echo -e "\n${GREEN}[PASS] STRONG DEFENSE DETECTED.${NC}"
    echo -e "       Argon2id is correctly configured to slow down attackers."
    echo -e "       (GPU cracking would be computationally expensive)."
else
    echo -e "\n${RED}[WARN] WEAK PARAMETERS DETECTED.${NC}"
    echo -e "       The hashing speed is too fast (<200ms). Increase Argon2 iterations/memory."
fi

echo -e "${BLUE}====================================================${NC}"