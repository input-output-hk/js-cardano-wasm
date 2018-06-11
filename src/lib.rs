#![feature(proc_macro, wasm_custom_section, wasm_import_module)]

extern crate wasm_bindgen;
extern crate wallet_crypto;

use wasm_bindgen::prelude::*;

use wallet_crypto::{*};

#[wasm_bindgen]
extern {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub struct XPrv(hdwallet::XPrv);
#[wasm_bindgen]
impl XPrv {
    pub fn from_daedalus_mnemonics(mnemonics: &str) -> Self {
        let mnemonics = bip39::Mnemonics::from_string(&bip39::dictionary::ENGLISH, mnemonics).unwrap();

        let entropy = bip39::Entropy::from_mnemonics(&mnemonics).unwrap();
        let entropy_cbor = cbor::encode_to_cbor(&cbor::Value::Bytes(cbor::Bytes::from_slice(entropy.as_ref()))).unwrap();
        let hash = hash::Blake2b256::new(&entropy_cbor);

        let seed = hdwallet::Seed::from_bytes(hash.into_bytes());
        let xprv = hdwallet::XPrv::generate_from_daedalus_seed(&seed);

        XPrv(xprv)
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        XPrv(hdwallet::XPrv::generate_from_seed(&hdwallet::Seed::from_slice(seed).unwrap()))
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        XPrv(hdwallet::XPrv::from_slice(bytes).unwrap())
    }

    pub fn to_hex(&self) -> String {
        util::hex::encode(self.0.as_ref())
    }

    pub fn from_hex(hex: &str) -> Self {
        XPrv(hdwallet::XPrv::from_slice(&util::hex::decode(hex).unwrap()).unwrap())
    }

    pub fn public(&self) -> XPub {
        XPub(self.0.public())
    }

    pub fn derive_v1(&self, index: u32) -> Self {
        XPrv(self.0.derive(hdwallet::DerivationScheme::V1, index))
    }

    pub fn derive_v2(&self, index: u32) -> Self {
        XPrv(self.0.derive(hdwallet::DerivationScheme::V2, index))
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(self.0.sign(msg))
    }
}

#[wasm_bindgen]
pub struct XPub(hdwallet::XPub);
#[wasm_bindgen]
impl XPub {
    pub fn from_slice(bytes: &[u8]) -> Self {
        XPub(hdwallet::XPub::from_slice(bytes).unwrap())
    }

    pub fn to_hex(&self) -> String {
        util::hex::encode(self.0.as_ref())
    }

    pub fn from_hex(hex: &str) -> Self {
        XPub(hdwallet::XPub::from_slice(&util::hex::decode(hex).unwrap()).unwrap())
    }

    pub fn derive_v1(&self, index: u32) -> Self {
        XPub(self.0.derive(hdwallet::DerivationScheme::V1 ,index).unwrap())
    }

    pub fn derive_v2(&self, index: u32) -> Self {
        XPub(self.0.derive(hdwallet::DerivationScheme::V2 ,index).unwrap())
    }

    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> bool {
        self.0.verify(&msg, &signature.0)
    }

    pub fn to_adddress(&self) -> Address {
        let addr_type = address::AddrType::ATPubKey;
        let sd = address::SpendingData::PubKeyASD(self.0.clone());
        let attrs = address::Attributes::new_bootstrap_era(None);

        Address(address::ExtendedAddr::new(addr_type, sd, attrs))
    }

    pub fn to_adddress_with_payload(&self, payload: &Payload) -> Address {
        let addr_type = address::AddrType::ATPubKey;
        let sd = address::SpendingData::PubKeyASD(self.0.clone());
        let attrs = address::Attributes::new_bootstrap_era(Some(payload.0.clone()));

        Address(address::ExtendedAddr::new(addr_type, sd, attrs))
    }
}

#[wasm_bindgen]
pub struct Signature(hdwallet::Signature<Vec<u8>>);
#[wasm_bindgen]
impl Signature {
    pub fn to_hex(&self) -> String {
        util::hex::encode(self.0.as_ref())
    }

    pub fn from_hex(hex: &str) -> Self {
        Signature(hdwallet::Signature::from_slice(&util::hex::decode(hex).unwrap()).unwrap())
    }
}

#[wasm_bindgen]
pub struct Payload(hdpayload::HDAddressPayload);
#[wasm_bindgen]
impl Payload {
    pub fn from_slice(bytes: &[u8]) -> Self {
        Payload(hdpayload::HDAddressPayload::from_bytes(bytes))
    }

    pub fn to_hex(&self) -> String {
        let r = util::hex::encode(self.0.as_ref());
        r
    }

    pub fn from_hex(hex: &str) -> Self {
        Payload(hdpayload::HDAddressPayload::from_bytes(&util::hex::decode(hex).unwrap()))
    }

    pub fn new(xpub: &XPub, path: &[u32]) -> Self {
        let key = hdpayload::HDKey::new(&xpub.0);
        let path = hdpayload::Path::new(Vec::from(path));
        Payload(key.encrypt_path(&path))
    }
}

#[wasm_bindgen]
pub struct Address(address::ExtendedAddr);
#[wasm_bindgen]
impl Address {
    pub fn to_base58(&self) -> String {
        util::base58::encode(&self.0.to_bytes())
    }

    pub fn from_base58(addr: &str) -> Self {
        let bytes = util::base58::decode(addr).unwrap();
        let addr  = cbor::decode_from_cbor(&bytes).unwrap();
        Address(addr)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        let addr  = cbor::decode_from_cbor(bytes).unwrap();
        Address(addr)
    }

    pub fn has_payload(&self) -> bool {
        self.0.attributes.derivation_path.is_some()
    }

    pub fn get_payload(&self) -> Payload {
        Payload(self.0.attributes.derivation_path.clone().unwrap())
    }
}

#[wasm_bindgen]
pub struct Addresses(Vec<String>);
#[wasm_bindgen]
impl Addresses {
    pub fn new() -> Self { Addresses(Vec::new()) }
    pub fn push(&mut self, s: &str) { self.0.push(s.to_owned())}
    pub fn len(&self) -> u32 { self.0.len() as u32 }
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
    pub fn pop(&mut self) -> String { self.0.pop().unwrap() }
}

#[wasm_bindgen]
pub struct RandomAddressChecker {
    key:              hdpayload::HDKey,
}
#[wasm_bindgen]
impl RandomAddressChecker {
    pub fn new(prv: XPrv) -> Self {
        let xprv = prv.0.clone();
        let xpub = xprv.public();
        let key  = hdpayload::HDKey::new(&xpub);
        RandomAddressChecker { key: key }
    }

    pub fn check_addresses(&self, addr: &Addresses) -> Addresses {
        Addresses(addr.0.iter().filter(|addr| self.check_address_base58(&addr)).cloned().collect())
    }

    pub fn check_address_base58(&self, base58_addr: &str) -> bool {
        self.check_address(&Address::from_base58(base58_addr))
    }

    pub fn check_address(&self, ref_addr: &Address) -> bool {
        let address = &ref_addr.0;

        if let Some(ref dp) = address.attributes.derivation_path {
            self.key.decrypt_path(dp).is_some()
        } else {
            false
        }
    }
}
