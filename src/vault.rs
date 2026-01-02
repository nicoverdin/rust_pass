use aes_gcm::{
    aead::{Aead, AeadCore, OsRng},
    Aes256Gcm,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

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
    /// Helper function to determine the storage path.
    /// Creates the directory structure if it doesn't exist.
    /// Returns: ~/.passrust/vault.json (Linux/Mac) or %USERPROFILE%\.passrust\vault.json (Windows)
    fn get_vault_path() -> PathBuf {
        let mut path = dirs::home_dir().expect("Could not determine home directory");
        path.push(".passrust");
        
        // Ensure the directory exists
        if !path.exists() {
            fs::create_dir_all(&path).expect("Failed to create vault directory");
        }
        
        path.push("vault.json");
        path
    }

    /// Loads the vault from the global user directory.
    /// If the file is missing or corrupted, it initializes a new `Vault` instance.
    pub fn load() -> Self {
        let path = Self::get_vault_path();
        
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

    /// Persists the current state of the vault to the global user directory.
    pub fn save(&self) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).expect("Failed to serialize vault");
        let path = Self::get_vault_path();
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())
    }

    /// Retrieves an entry by site name (case-insensitive).
    pub fn find_entry(&self, site: &str) -> Option<&PasswordEntry> {
        self.entries
            .iter()
            .find(|e| e.site.to_lowercase() == site.to_lowercase())
    }

    /// Updates the password for an existing site.
    pub fn update_entry(&mut self, site: &str, new_pass: &str, cipher: &Aes256Gcm) -> bool {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.site.to_lowercase() == site.to_lowercase())
        {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ciphertext = cipher
                .encrypt(&nonce, new_pass.as_bytes())
                .expect("Encryption failed");

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
        self.entries
            .retain(|e| e.site.to_lowercase() != site.to_lowercase());
        self.entries.len() < initial_len
    }
}