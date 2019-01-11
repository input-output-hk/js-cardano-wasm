#![cfg(target_arch = "wasm32")]

extern crate cardano_wallet;
extern crate wasm_bindgen;
extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;

use cardano_wallet::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn public_key_to_address() {
    const REDEEM_HEX : &'static str = "fb40490e2fa06aeca59382e9b504e08cc7a8ee463d95309b66fd76bf03924d99";
    const ADDRESS : &'static str = "Ae2tdPwUPEZHFQnrr2dYB4GEQ8WVKspEyrg29pJ3f7qdjzaxjeShEEokF5f";

    let blockchain_settings = BlockchainSettings::mainnet();
    let key = PublicRedeemKey::from_hex(REDEEM_HEX).unwrap();
    let address = key.address(&blockchain_settings);
    let address_base58 = address.to_base58();

    assert_eq!(ADDRESS, address_base58);
}
