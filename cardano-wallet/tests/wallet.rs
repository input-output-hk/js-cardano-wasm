//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate cardano_wallet;
extern crate wasm_bindgen;
extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

use cardano_wallet::*;

wasm_bindgen_test_configure!(run_in_browser);

const MNEMONICS: &'static str = "crowd captain hungry tray powder motor coast oppose month shed parent mystery torch resemble index";
const ENTROPY: [u8;20] = [
    0x34, 0x44, 0x45, 0xbd, 0x73, 0xda, 0x93, 0x20, 0xcb, 0x34, 0xdc, 0x8f, 0x78, 0xaa, 0x80, 0xc9,
    0x3e, 0x55, 0x6e, 0x9c,
];
const PASSWORD: &'static str = "Cardano Rust for the winners!";

#[wasm_bindgen_test]
fn mnemonics_invalid_checksum() {
    const INVALID_MNEMONICS: &'static str = "crowd captain hungry tray zero motor coast oppose zero zero parent mystery torch resemble abandon";
    assert!(Entropy::from_english_mnemonics(INVALID_MNEMONICS).is_err());
}
#[wasm_bindgen_test]
fn mnemonics_invalid_length() {
    const INVALID_MNEMONICS: &'static str = "crowd captain hungry tray zero motor coast oppose";
    assert!(Entropy::from_english_mnemonics(INVALID_MNEMONICS).is_err());
}
#[wasm_bindgen_test]
fn recover_mnemonics() {
    let entropy = Entropy::from_english_mnemonics(MNEMONICS).unwrap();
    // TODO: check entropy
}

#[wasm_bindgen_test]
fn recover_root_key() {
    let entropy = Entropy::from_english_mnemonics(MNEMONICS).unwrap();
    let root_key = Bip44RootPrivateKey::recover(&entropy, PASSWORD).unwrap();
}
