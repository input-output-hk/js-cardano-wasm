//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate cardano_wallet;
extern crate wasm_bindgen;
extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

use cardano_wallet::*;

wasm_bindgen_test_configure!(run_in_browser);

const MESSAGE: &'static str = "crowd captain hungry tray powder motor coast oppose month shed parent mystery torch resemble index";
const PASSWORD: &'static str = "Cardano Rust for the winners!";
const SALT: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
];
const NONCE: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1];

#[wasm_bindgen_test]
fn encrypt_decrypt_with_password_success() {
    let encrypted = password_encrypt(PASSWORD, &SALT, &NONCE, MESSAGE.as_bytes()).unwrap();
    let encrypted: Vec<u8> = encrypted.into_serde().unwrap();
    let decrypted = password_decrypt(PASSWORD, &encrypted).unwrap();
    let decrypted: Vec<u8> = decrypted.into_serde().unwrap();

    assert_eq!(MESSAGE.as_bytes(), decrypted.as_slice());
}
#[wasm_bindgen_test]
fn encrypt_with_password_invalid_salt() {
    const INVALID_SALT: [u8; 31] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        0,
    ];

    assert!(password_encrypt(PASSWORD, &INVALID_SALT, &NONCE, MESSAGE.as_bytes()).is_err());
}
#[wasm_bindgen_test]
fn encrypt_with_password_invalid_nonce() {
    const INVALID_NONCE: [u8; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2];

    assert!(password_encrypt(PASSWORD, &SALT, &INVALID_NONCE, MESSAGE.as_bytes()).is_err());
}
#[wasm_bindgen_test]
fn encrypt_decrypt_with_password_invalid_password() {
    const INVALID_PASSWORD: &'static str = "This is just so wrong...";

    let encrypted = password_encrypt(PASSWORD, &SALT, &NONCE, MESSAGE.as_bytes()).unwrap();
    let encrypted: Vec<u8> = encrypted.into_serde().unwrap();
    assert!(password_decrypt(INVALID_PASSWORD, &encrypted).is_err());
}
