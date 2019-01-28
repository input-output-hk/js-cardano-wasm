#![cfg(target_arch = "wasm32")]

extern crate cardano_wallet;
extern crate wasm_bindgen;
extern crate wasm_bindgen_test;
#[macro_use]
extern crate lazy_static;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

use cardano_wallet::*;

wasm_bindgen_test_configure!(run_in_browser);

struct Test {
    iv: Vec<u8>,
    password: &'static str,
    entropy: Entropy,
}
lazy_static! {
    static ref TESTS: Vec<Test> = {
        vec![
            Test {
                iv: vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                password: "",
                entropy: Entropy::from_english_mnemonics(
                    "legal winner thank year wave sausage worth useful legal winner thank yellow",
                ).unwrap()
            },
            Test {
                iv: vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
                password: "Cardano Ada",
                entropy: Entropy::from_english_mnemonics(
                    "fold parrot feature figure stay blanket woman grain huge orphan key exile"
                ).unwrap()
            },
            Test {
                iv: vec![0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a],
                password: "This is a very long passphrase. This is a very long passphrase. This is a very long passphrase. This is a very long passphrase.",
                entropy: Entropy::from_english_mnemonics(
                    "clay eyebrow melody february pencil betray build cart insane great coconut champion ancient catch provide horn merit cinnamon"
                ).unwrap()
            },
        ]
    };
}

fn test(i: usize) {
    let test = &TESTS[i];
    let bytes = paper_wallet_scramble(&test.entropy, &test.iv, test.password).unwrap();
    let bytes: Vec<u8> = JsValue::into_serde(&bytes).unwrap();
    let entropy = paper_wallet_unscramble(&bytes, test.password).unwrap();

    assert_eq!(&test.entropy, &entropy);
}

#[wasm_bindgen_test]
fn test_valid_test_0() {
    test(0)
}
#[wasm_bindgen_test]
fn test_valid_test_1() {
    test(1)
}
#[wasm_bindgen_test]
fn test_valid_test_2() {
    test(2)
}
