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