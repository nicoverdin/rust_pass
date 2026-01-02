use aes_gcm::{aead::KeyInit, Aes256Gcm, Key};
use argon2::{password_hash::{PasswordHasher, SaltString}, Argon2};

pub fn get_cipher(master_pass: &str, salt_str: &str) -> Aes256Gcm {
    let salt = SaltString::from_b64(salt_str).expect("Corrupted salt in vault");
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(master_pass.as_bytes(), &salt)
        .expect("Failed to derive key");
    
    let hash_output = password_hash.hash.expect("Hash output missing");
    let hash_bytes = hash_output.as_bytes();
    
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&hash_bytes[..32]))
}

pub fn generate_password(length: usize) -> String {
    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rand::Rng::gen_range(&mut rng, 0..charset.len());
            charset.chars().nth(idx).unwrap()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::{Aead, AeadCore, OsRng};

    #[test]
    fn test_encryption_decryption_cycle() {
        let master_pass = "portfolio_password_2026";
        let salt = "somesaltstandardbase64"; // Sal de prueba
        let data = "secret_message";

        let cipher = get_cipher(master_pass, salt);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, data.as_bytes()).unwrap();
        
        let decrypted_bytes = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        let decrypted_string = String::from_utf8(decrypted_bytes).unwrap();

        assert_eq!(data, decrypted_string);
    }

    #[test]
    fn test_wrong_password_fails() {
        let salt = "somesaltstandardbase64";
        let cipher_correct = get_cipher("password123", salt);
        let cipher_wrong = get_cipher("wrong_pass", salt);
        
        let data = "sensitive data";
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher_correct.encrypt(&nonce, data.as_bytes()).unwrap();

        let result = cipher_wrong.decrypt(&nonce, ciphertext.as_ref());
        assert!(result.is_err());
    }
}