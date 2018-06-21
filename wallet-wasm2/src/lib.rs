#![feature(proc_macro, wasm_custom_section, wasm_import_module)]

extern crate wasm_bindgen;
extern crate wallet_crypto;
#[macro_use]
extern crate raw_cbor;

use wasm_bindgen::prelude::*;

use wallet_crypto::{*};

#[wasm_bindgen]
extern {
    // import JS's `console.error` function so we can use it in the `handle_result'
    // macro to report error happened before panic.
    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
}

// macro to handle `Result`. This is because it is not possible to return
// an enum to JS yet. This macro may change if we find out how to handle
// error in a better way.
macro_rules! handle_result {
    ($r:expr) => ({
        match $r {
            Err(err) => {
                error(&format!("{}:{}: `{}'\n  /!\\ {:?}", file!(), line!(), stringify!($r), err));
                panic!("function failed...")
            },
            Ok(k) => k
        }
    })
}

// expose the main features of the HDWallet's XPrv.
#[wasm_bindgen]
pub struct XPrv(hdwallet::XPrv);
#[wasm_bindgen]
impl XPrv {
    // this is a bit of a kitchen sink function and may be changed in the future
    pub fn from_daedalus_mnemonics(mnemonics: &str) -> Self {
        let mnemonics = handle_result!(bip39::Mnemonics::from_string(&bip39::dictionary::ENGLISH, mnemonics));
        let entropy = handle_result!(bip39::Entropy::from_mnemonics(&mnemonics));

        let entropy_cbor = handle_result!(cbor!(entropy.as_ref()));
        let seed = hash::Blake2b256::new(entropy_cbor.as_ref());
        let seed = handle_result!(cbor!(seed.as_ref()));
        let xprv = hdwallet::XPrv::generate_from_daedalus_seed(&seed);

        XPrv(xprv)
    }

    pub fn from_seed(seed: &[u8]) -> Self {
        let seed = handle_result!(hdwallet::Seed::from_slice(seed));
        XPrv(hdwallet::XPrv::generate_from_seed(&seed))
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        let xprv = handle_result!(hdwallet::XPrv::from_slice(bytes));
        XPrv(xprv)
    }

    pub fn to_hex(&self) -> String {
        util::hex::encode(self.0.as_ref())
    }

    pub fn from_hex(hex: &str) -> Self {
        let bytes = handle_result!(util::hex::decode(hex));
        let xprv  = handle_result!(hdwallet::XPrv::from_slice(&bytes));
        XPrv(xprv)
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

    pub fn sign_str(&self, msg: &str) -> Signature {
        Signature(self.0.sign(msg.as_bytes()))
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
        let xpub = handle_result!(hdwallet::XPub::from_slice(bytes));
        XPub(xpub)
    }

    pub fn to_hex(&self) -> String {
        util::hex::encode(self.0.as_ref())
    }

    pub fn from_hex(hex: &str) -> Self {
        let bytes = handle_result!(util::hex::decode(hex));
        let xpub = handle_result!(hdwallet::XPub::from_slice(&bytes));
        XPub(xpub)
    }

    pub fn derive_v1(&self, index: u32) -> Self {
        XPub(handle_result!(self.0.derive(hdwallet::DerivationScheme::V1 ,index)))
    }

    pub fn derive_v2(&self, index: u32) -> Self {
        XPub(handle_result!(self.0.derive(hdwallet::DerivationScheme::V2 ,index)))
    }

    pub fn verify_str(&self, signature: &Signature, msg: &str) -> bool {
        self.0.verify(msg.as_bytes(), &signature.0)
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
        let bytes = handle_result!(util::hex::decode(hex));
        let signature = handle_result!(hdwallet::Signature::from_slice(&bytes));
        Signature(signature)
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
        let bytes = handle_result!(util::hex::decode(hex));
        Payload(hdpayload::HDAddressPayload::from_bytes(&bytes))
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
        let bytes = handle_result!(util::base58::decode(addr));
        let addr  = handle_result!(raw_cbor::de::RawCbor::from(&bytes).deserialize());
        Address(addr)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        let addr  = handle_result!(raw_cbor::de::RawCbor::from(bytes).deserialize());
        Address(addr)
    }

    pub fn has_payload(&self) -> bool {
        self.0.attributes.derivation_path.is_some()
    }

    pub fn get_payload(&self) -> Payload {
        match &self.0.attributes.derivation_path {
            Some(ref dp) => Payload(dp.clone()),
            None         => {
                error("This Address has no derivation path, use `has_payload` to check presence of dervation path first");
                panic!("no derivation path")
            }
        }
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
    pub fn pop(&mut self) -> String {
        match self.0.pop() {
            Some(addr) => addr,
            None => {
                error("No more addresses, use `is_empty` before calling `pop` to prevent this error.");
                panic!("No more addresses...")
            }
        }
    }
}

#[wasm_bindgen]
pub struct RandomAddressChecker {
    key: hdpayload::HDKey,
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
