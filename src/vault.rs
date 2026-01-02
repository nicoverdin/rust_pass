use aes_gcm::{aead::{Aead, AeadCore, OsRng}, Aes256Gcm};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordEntry {
    pub site: String,
    pub username: String,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Vault {
    pub salt: String,
    pub entries: Vec<PasswordEntry>,
}

impl Vault {
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

    pub fn save(&self) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).expect("Failed to serialize");
        let mut file = File::create("vault.json")?;
        file.write_all(json.as_bytes())
    }

    pub fn find_entry(&self, site: &str) -> Option<&PasswordEntry> {
        self.entries.iter().find(|e| e.site.to_lowercase() == site.to_lowercase())
    }

    // MÉTODO: UPDATE
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

    // MÉTODO: DELETE
    pub fn delete_entry(&mut self, site: &str) -> bool {
        let initial_len = self.entries.len();
        self.entries.retain(|e| e.site.to_lowercase() != site.to_lowercase());
        self.entries.len() < initial_len
    }
}