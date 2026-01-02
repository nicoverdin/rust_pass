#!/bin/bash
# Security Test 03: Memory Remanence

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Busca el binario
if [ -f "../target/release/rust_pass" ]; then
    BIN="../target/release/rust_pass"
elif [ -f "./target/release/rust_pass" ]; then
    BIN="./target/release/rust_pass"
else
    echo "Error: Binary not found."
    exit 1
fi

# Configuración
DUMP_NAME="memory_dump"
DUMP_PATH="$(pwd)/$DUMP_NAME"
CANARY="SECRET_KEY_IN_RAM_12345"

echo -e "${BLUE}====================================================${NC}"
echo -e "${YELLOW}   SECURITY TEST 03: MEMORY DUMPING (RAM)            ${NC}"
echo -e "${BLUE}====================================================${NC}"

# Limpieza
pkill -f rust_pass > /dev/null 2>&1
rm -f "${DUMP_PATH}"*
rm -f "$HOME/.passrust/vault.json"

echo -e "1. [SETUP] Launching PassRust..."
echo -e "   Injecting Secret: '${YELLOW}$CANARY${NC}'"

# Lanzamos el programa en segundo plano (&)
# Como hemos puesto el sleep en Rust, se quedará vivo 10 segundos.
# Enviamos la contraseña 2 veces por si pide confirmación al ser vault nuevo.
printf "$CANARY\n$CANARY\n" | $BIN add bank.com user 123 > /dev/null 2>&1 &
PID=$!

echo -e "   Target PID: $PID"
echo -e "   Waiting for the secret to settle in RAM..."
sleep 2 # Esperamos un poco a que Rust cargue la variable

# Verificamos si sigue vivo
if ! ps -p $PID > /dev/null; then
    echo -e "${RED}[ERROR] Process died too fast (Check your Rust sleep code).${NC}"
    exit 1
fi

echo -e "\n2. [ATTACK] Dumping memory..."
if sudo gcore -o "$DUMP_PATH" $PID > /dev/null 2>&1; then
    echo -e "   Dump successful."
else
    echo -e "${RED}[ERROR] gcore failed.${NC}"
    kill $PID
    exit 1
fi

# Matamos el proceso (ya no lo necesitamos)
kill $PID > /dev/null 2>&1

# Análisis
GENERATED_FILE=$(ls "${DUMP_PATH}"* 2>/dev/null | head -n 1)
echo -e "\n3. [ANALYSIS] Scanning dump..."

if strings "$GENERATED_FILE" | grep -q "$CANARY"; then
    echo -e "\n${RED}[FAIL] VULNERABILITY CONFIRMED!${NC}"
    echo -e "       Found '${YELLOW}$CANARY${NC}' in plain text in RAM."
else
    echo -e "\n${GREEN}[PASS] SECURE!${NC}"
    echo -e "       Secret NOT found."
fi

rm -f "${DUMP_PATH}"*