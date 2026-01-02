use aes_gcm::{Aes256Gcm, Key, aead::KeyInit};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};

/// Derives a 256-bit AES key from a master password and a salt using Argon2id.
///
/// # Security
/// Uses the Argon2id variant, which is the winner of the Password Hashing Competition.
/// It is designed to be memory-hard, making it highly resistant to GPU and ASIC
/// brute-force attacks.
///
/// # Arguments
/// * `master_pass` - The user's secret master password.
/// * `salt_str` - The Base64 encoded salt string stored in the vault.
pub fn get_cipher(master_pass: &str, salt_str: &str) -> Aes256Gcm {
    let salt = SaltString::from_b64(salt_str).expect("Invalid salt");

    // CONFIGURACIÓN ENDURECIDA (HARDENED)
    // m_cost: 65536 KB = 64 MB de RAM por hash.
    // t_cost: 3 iteraciones.
    // p_cost: 4 hilos de paralelismo.
    let params = Params::new(131072, 8, 4, Some(32)).expect("Invalid Argon2 params");

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let password_hash = argon2
        .hash_password(master_pass.as_bytes(), &salt)
        .expect("Failed to derive key");

    let hash_output = password_hash.hash.expect("Hash output missing");
    let hash_bytes = hash_output.as_bytes();

    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&hash_bytes[..32]))
}
/// Generates a high-entropy random password using a cryptographically secure character set.
///
/// # Arguments
/// * `length` - The desired number of characters for the password.
///
/// # Example
/// ```
/// let pass = crypto::generate_password(16);
/// assert_eq!(pass.len(), 16);
/// ```
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
    use argon2::password_hash::SaltString;

    #[test]
    fn test_encryption_decryption_cycle() {
        let master_pass = "portfolio_password_2026";
        let salt = SaltString::generate(&mut OsRng);
        let salt_str = salt.as_str();
        let data = "secret_message";

        let cipher = get_cipher(master_pass, salt_str);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, data.as_bytes()).unwrap();
        let decrypted_bytes = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        let decrypted_string = String::from_utf8(decrypted_bytes).unwrap();

        assert_eq!(data, decrypted_string);
    }

    #[test]
    fn test_wrong_password_fails() {
        let salt = SaltString::generate(&mut OsRng);
        let salt_str = salt.as_str();

        let cipher_correct = get_cipher("password123", salt_str);
        let cipher_wrong = get_cipher("wrong_pass", salt_str);

        let data = "sensitive data";
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher_correct.encrypt(&nonce, data.as_bytes()).unwrap();

        let result = cipher_wrong.decrypt(&nonce, ciphertext.as_ref());
        assert!(result.is_err());
    }
}
