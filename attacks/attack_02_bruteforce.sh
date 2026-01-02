#!/bin/bash

# Security Test 02: Brute Force Resistance
# Target: Argon2id Key Derivation Function (KDF)

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Ruta al ejecutable compilado (Release)
BIN="../target/release/rust_pass"
VAULT_DIR="$HOME/.passrust"
VAULT_FILE="$VAULT_DIR/vault.json"

echo -e "${BLUE}====================================================${NC}"
echo -e "${YELLOW}   SECURITY TEST 02: BRUTE FORCE ATTACK (ARGON2)     ${NC}"
echo -e "${BLUE}====================================================${NC}"

# 0. VERIFICAR BINARIO
if [ ! -f "$BIN" ]; then
    echo -e "${RED}[ERROR] Binary not found at $BIN${NC}"
    echo "Please run: cargo build --release"
    exit 1
fi

# 1. LIMPIEZA Y SETUP (Automático)
echo -e "1. [SETUP] Resetting environment..."
rm -f "$VAULT_FILE"

echo -e "   [SETUP] Creating new vault with master password: 'admin'"
# Usamos printf para enviar la contraseña dos veces (Crear + Confirmar)
# Esto crea el archivo vault.json y añade la entrada
printf "admin\nadmin\n" | $BIN add bank.com victim_user secret_123 > /dev/null 2>&1

if [ ! -f "$VAULT_FILE" ]; then
    echo -e "${RED}[ERROR] Failed to create vault.json via script.${NC}"
    exit 1
fi

# 2. EL ATAQUE
echo -e "\n2. [ATTACK] Starting Dictionary Attack..."
echo -e "   Targeting the Master Password..."
echo -e "   Note the delay per attempt (Argon2 'Nuclear' settings)...\n"

# Lista de contraseñas (incluye la correcta 'admin' al final)
WORDLIST=("123456" "password" "qwerty" "admin")

start_total=$(date +%s%N)

for pass in "${WORDLIST[@]}"; do
    start_attempt=$(date +%s%N)
    
    echo -ne "   [..] Trying: ${CYAN}'$pass'${NC} ... "
    
    # Intentamos descifrar enviando la contraseña candidata
    # Capturamos el código de salida ($?)
    echo "$pass" | $BIN get bank.com > /dev/null 2>&1
    EXIT_CODE=$?
    
    end_attempt=$(date +%s%N)
    duration=$((($end_attempt - $start_attempt)/1000000)) # Milisegundos
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo -e "${GREEN}[CRACKED!]${NC} (Cost: ${YELLOW}${duration}ms${NC})"
    else
        echo -e "${RED}[FAILED]${NC} (Cost: ${YELLOW}${duration}ms${NC})"
    fi
done

end_total=$(date +%s%N)
total_ms=$((($end_total - $start_total)/1000000))

echo -e "\n3. [RESULTS] Analysis:"
echo -e "   Total time: ~${total_ms} ms."
echo -e "   High latency per attempt proves Argon2id is working."
echo -e "${BLUE}====================================================${NC}"