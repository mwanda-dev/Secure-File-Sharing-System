use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    aes::cipher,
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use std::fs;

fn derive_key(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

#[tauri::command]
fn encrypt_file(path: String, password: String) -> Result<(), String> {
    let data = fs::read(&path).map_err(|e| e.to_string())?;
    let key = derive_key(&password);
    let cipher = Aes256Gcm::new(&key.into());

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &data,
                aad: b"",
            },
        )
        .map_err(|e| e.to_string())?;

    let mut out = nonce_bytes.to_vec();
    out.extend(ciphertext);

    fs::write(format!("{}.enc", path), out).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn decrypt_file(path: String, password: String) -> Result<(), String> {
    let blob = fs::read(&path).map_err(|e| e.to_string())?;
    if blob.len() < 12 {
        return Err("Invalid File".into());
    }

    let (nonce_bytes, cipher_text) = blob.split_at(12);
    let key = derive_key(&password);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: cipher_text,
                aad: b"",
            },
        )
        .map_err(|_| "Decryption failed")?;

    let output_path = path.trim_end_matches(".enc");
    fs::write(output_path, plaintext).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![])
        .run(tauri::generate_context!())
        .expect("Error while running tauri application");
}
