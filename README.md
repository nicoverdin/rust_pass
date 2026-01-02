# PassRust: Secure CLI Password Manager

[![Rust CI](https://github.com/nicoverdin/rust_pass/actions/workflows/rust.yml/badge.svg)](https://github.com/nicoverdin/rust_pass/actions/workflows/rust.yml)
[![Deploy Documentation](https://github.com/nicoverdin/rust_pass/actions/workflows/docs.yml/badge.svg)](https://github.com/nicoverdin/rust_pass/actions/workflows/docs.yml)
📚 [Documentation Live Demo](https://nicoverdin.github.io/rust_pass/rust_pss/)

---

A lightweight, secure command-line password manager built with **Rust**. This project focuses on high-performance cryptography, safe memory management, and a user-friendly hybrid interface.

## Features
* **Zero Trust Architecture**: Passwords are encrypted locally using AES-256-GCM.
* **Hybrid Interface**: Use CLI arguments for automation or a rich **Interactive Mode** with menus and forms.
* **Argon2 KDF**: Industry-standard key derivation that is resistant to GPU brute-force attacks.
* **Full CRUD Operations**: Create, Read, Update, and Delete entries with ease.
* **Secure Input**: Master password and credential inputs are hidden from the terminal history and shoulder-surfing.
* **Password Generator**: Built-in utility to create high-entropy, cryptographically secure passwords.

## Technical Specifications

| Component | Implementation |
| :--- | :--- |
| **Language** | Rust |
| **Encryption** | AES-256-GCM (Authenticated Encryption) |
| **Key Derivation** | Argon2id (Memory-hard hashing) |
| **Persistence** | Structured JSON with Salt persistence |
| **Interactive UI** | Dialoguer (Menus, Hidden Inputs) |



## Project Structure
The project is modularized to ensure a clean separation of concerns:
* `main.rs`: Orchestrates the CLI/Interactive flow and command execution.
* `vault.rs`: Manages the encrypted data model, file I/O, and entry logic.
* `crypto.rs`: Handles Argon2 key derivation and AES-256-GCM encryption/decryption.

## Installation

Ensure you have the Rust toolchain installed.

`git clone https://github.com/yourusername/passrust.git`
`cd passrust`
`cargo build --release`

The binary will be available at `./target/release/passrust`.

## Usage

PassRust supports two modes of operation:

### 1. Interactive Mode (Recommended)
Simply run the program without arguments to enter the interactive menu:
`./passrust`

### 2. CLI Mode (Arguments)
For quick actions or scripting:
`passrust add google myuser mypassword`
`passrust get google`
`passrust update google newpassword`
`passrust delete google`
`passrust list`
`passrust gen 24`

## Security Design Choices

### Why AES-256-GCM?
Standard AES only provides confidentiality. **GCM (Galois/Counter Mode)** provides **Authenticated Encryption**, meaning it ensures both confidentiality and integrity. If the `vault.json` file is tampered with by even a single bit, the decryption will fail, preventing the injection of corrupted or malicious data.



### Why Argon2?
Unlike SHA-256 or PBKDF2, **Argon2** is designed to be memory-hard. It requires a significant amount of RAM to compute, making it extremely expensive and slow for attackers to use specialized hardware (GPUs or ASICs) to crack your master password.

### Nonce Management
Each entry is encrypted with a unique **96-bit Nonce**. Reusing a nonce with the same key is a critical security failure in GCM. PassRust generates a new random nonce for every single `add` or `update` operation to ensure cryptographic strength.

---
License: MIT