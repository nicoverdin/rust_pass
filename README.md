# PassRust: Secure CLI Password Manager

[![Rust CI](https://github.com/nicoverdin/rust_pass/actions/workflows/rust.yml/badge.svg)](https://github.com/nicoverdin/rust_pass/actions/workflows/rust.yml)
[![Deploy Documentation](https://github.com/nicoverdin/rust_pass/actions/workflows/docs.yml/badge.svg)](https://github.com/nicoverdin/rust_pass/actions/workflows/docs.yml)

## 📚 [Documentation Live Demo](https://nicoverdin.github.io/rust_pass/rust_pass/)

---

A lightweight, secure command-line password manager built with **Rust**. This project focuses on high-performance cryptography, safe memory management, and a user-friendly hybrid interface.

## 🧠 Key Learnings & Technical Challenges

### 🛡️ Cryptographic Integrity with AES-256-GCM
Unlike standard AES-CBC, I implemented **AES-256-GCM** (Galois/Counter Mode). This provides not only confidentiality but also **authenticity**. It prevents "bit-flipping" attacks by using an authentication tag, ensuring that if the encrypted vault is tampered with, the system will detect it and refuse to decrypt.

### 🔑 Robust Key Derivation with Argon2id
To protect against GPU-based brute-force attacks, I integrated **Argon2id**, the winner of the Password Hashing Competition. This ensures that even if a master password is weak, the computational cost (memory-hard) makes offline cracking significantly harder.

### 🦀 Rust Memory Safety & Ownership
Developing this manager required a deep understanding of Rust's ownership model, especially when handling sensitive data in memory. I used `Zeroize` (optional but recommended) concepts to ensure that plaintext passwords are not left lingering in the heap after use.

### 🤖 Automated DevOps Pipeline
I established a professional CI/CD workflow that:
- Runs automated unit tests on every push.
- Enforces code style consistency using `cargo fmt`.
- Automatically deploys technical documentation to GitHub Pages.

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

## 🚀 Installation

To install **PassRust** on your local machine, clone the repository and run the installation script:

`git clone https://github.com/nicoverdin/rust_pass.git`
`cd rust_pass`
`chmod +x install.sh`
`./install.sh`

Once installed, simply run:
`passrust`

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

## 🗺️ Roadmap & Future Enhancements

The current version (v1.1) provides a solid cryptographic foundation. Future iterations will focus on portability and advanced security auditing:

- [ ] **Cloud Sync Integration**: Optional encrypted synchronization with providers like Google Drive or Dropbox using their respective APIs.
- [ ] **Password Health Audit**: A feature to scan the vault and alert users about weak, reused, or compromised passwords (via HaveIBeenPwned API).
- [ ] **Browser Extension Bridge**: A secure WebSocket local server to allow browser extensions to request credentials safely.
- [ ] **Multi-factor Authentication (MFA)**: Support for TOTP (Time-based One-Time Passwords) within the vault.
- [ ] **Zero-Knowledge Recovery**: Implementation of a BIP-39 recovery phrase system for master password loss.
- [ ] **Cross-Platform GUI**: A native desktop interface built with **Tauri** using the existing Rust core.