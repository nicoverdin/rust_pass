#!/bin/bash

# PassRust Installer
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' 

echo -e "${BLUE}--- Installing PassRust ---${NC}"

if ! command -v cargo &> /dev/null
then
    echo "Error: Rust/Cargo is not installed."
    exit
fi

echo -e "${BLUE}Building in release mode...${NC}"
cargo build --release

echo -e "${BLUE}Installing binary to /usr/local/bin...${NC}"

if [ -f "/usr/local/bin/passrust" ]; then
    sudo rm -f /usr/local/bin/passrust
fi

# Copiamos el nuevo
sudo cp target/release/rust_pass /usr/local/bin/passrust

echo -e "${GREEN}Installation complete!${NC}"
echo -e "You can now run the manager by typing: ${BLUE}passrust${NC}"