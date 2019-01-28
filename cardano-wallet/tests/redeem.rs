#![cfg(target_arch = "wasm32")]

extern crate cardano_wallet;
extern crate wasm_bindgen;
extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

use cardano_wallet::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn public_key_to_address() {
    const REDEEM_HEX: &'static str =
        "fb40490e2fa06aeca59382e9b504e08cc7a8ee463d95309b66fd76bf03924d99";
    const ADDRESS: &'static str = "Ae2tdPwUPEZHFQnrr2dYB4GEQ8WVKspEyrg29pJ3f7qdjzaxjeShEEokF5f";

    let blockchain_settings = BlockchainSettings::mainnet();
    let key = PublicRedeemKey::from_hex(REDEEM_HEX).unwrap();
    let address = key.address(&blockchain_settings);
    let address_base58 = address.to_base58();

    assert_eq!(ADDRESS, address_base58);
}

#[wasm_bindgen_test]
fn private_key_decode() {
    const REDEEM_HEX: &'static str =
        "96555162f5bb2c0caa98332750ebebb398a1e0e1df2e22d9af3e4d4fe891b93c";

    let blockchain_settings = BlockchainSettings::mainnet();
    let private_key = PrivateRedeemKey::from_hex(REDEEM_HEX).unwrap();
    let public_key = private_key.public();
    let address = public_key.address(&blockchain_settings);
    let address_base58 = address.to_base58();

    let signature = private_key.sign(address_base58.as_bytes());

    assert!(public_key.verify(address_base58.as_bytes(), &signature));
}
