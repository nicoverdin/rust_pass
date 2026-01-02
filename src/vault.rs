use aes_gcm::{aead::{Aead, AeadCore, OsRng}, Aes256Gcm};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};

/// Represents an individual encrypted credential entry.
#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordEntry {
    pub site: String,
    pub username: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// Core structure for managing the encrypted password database.
#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub salt: String,
    pub entries: Vec<PasswordEntry>,
}

impl Vault {
    /// Loads the vault from `vault.json`. 
    /// If the file is missing or corrupted, it initializes a new `Vault` instance.
    pub fn load() -> Self {
        let path = "vault.json";
        File::open(path)
            .and_then(|mut file| {
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                Ok(serde_json::from_str(&contents).unwrap_or_else(|_| Self::new()))
            })
            .unwrap_or_else(|_| Self::new())
    }

    fn new() -> Self {
        Self {
            salt: argon2::password_hash::SaltString::generate(&mut OsRng).to_string(),
            entries: Vec::new(),
        }
    }

    /// Persists the current state of the vault to a JSON file.
    pub fn save(&self) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).expect("Failed to serialize");
        let mut file = File::create("vault.json")?;
        file.write_all(json.as_bytes())
    }

    /// Retrieves an entry by site name (case-insensitive).
    pub fn find_entry(&self, site: &str) -> Option<&PasswordEntry> {
        self.entries.iter().find(|e| e.site.to_lowercase() == site.to_lowercase())
    }

    /// Updates the password for an existing site.
    /// Returns `true` if the entry was found and updated successfully.
    pub fn update_entry(&mut self, site: &str, new_pass: &str, cipher: &Aes256Gcm) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.site.to_lowercase() == site.to_lowercase()) {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ciphertext = cipher.encrypt(&nonce, new_pass.as_bytes()).expect("Encryption failed");

            entry.ciphertext = ciphertext;
            entry.nonce = nonce.to_vec();
            true
        } else {
            false
        }
    }

    /// Removes an entry from the vault.
    pub fn delete_entry(&mut self, site: &str) -> bool {
        let initial_len = self.entries.len();
        self.entries.retain(|e| e.site.to_lowercase() != site.to_lowercase());
        self.entries.len() < initial_len
    }
}