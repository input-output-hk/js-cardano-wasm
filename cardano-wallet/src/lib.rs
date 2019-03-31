extern crate cfg_if;
extern crate serde;
extern crate wasm_bindgen;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate cbor_event;
extern crate cardano;
extern crate cryptoxide;

mod utils;

use cfg_if::cfg_if;
use cryptoxide::{chacha20poly1305::ChaCha20Poly1305, hmac::Hmac, pbkdf2::pbkdf2, sha2::Sha512};
use wasm_bindgen::prelude::*;

use self::cardano::{
    address,
    bip::{bip39, bip44},
    coin, config, fee, hash, hdpayload, hdwallet, paperwallet, tx, txbuild, txutils, util, wallet,
};

/// setting of the blockchain
///
/// This includes the `ProtocolMagic` a discriminant value to differentiate
/// different instances of the cardano blockchain (Mainnet, Testnet... ).
#[wasm_bindgen]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockchainSettings {
    /// code of a specific blockchain used to sign transactions and blocks
    protocol_magic: config::ProtocolMagic,
}
#[wasm_bindgen]
impl BlockchainSettings {
    /// serialize into a JsValue object. Allowing the client to store the settings
    /// or see changes in the settings or change the settings.
    ///
    /// Note that this is not recommended to change the settings on the fly. Doing
    /// so you might not be able to recover your funds anymore or to send new
    /// transactions.
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        JsValue::from_serde(self).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    /// retrieve the object from a JsValue.
    pub fn from_json(value: JsValue) -> Result<BlockchainSettings, JsValue> {
        value
            .into_serde()
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    /// default settings to work with Cardano Mainnet
    pub fn mainnet() -> BlockchainSettings {
        BlockchainSettings {
            protocol_magic: config::ProtocolMagic::default(),
        }
    }
}

/// There is a special function to use when deriving Addresses. This function
/// has been revised to offer stronger properties. This is why there is a
/// V2 derivation scheme. The V1 being the legacy one still used in daedalus
/// now a days.
///
/// It is strongly advised to use V2 as the V1 is deprecated since April 2018.
/// Its support is already provided for backward compatibility with old
/// addresses.
#[wasm_bindgen]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationScheme(hdwallet::DerivationScheme);
#[wasm_bindgen]
impl DerivationScheme {
    /// deprecated, provided here only for backward compatibility with
    /// Daedalus' addresses
    pub fn v1() -> DerivationScheme {
        DerivationScheme(hdwallet::DerivationScheme::V1)
    }

    /// the recommended settings
    pub fn v2() -> DerivationScheme {
        DerivationScheme(hdwallet::DerivationScheme::V2)
    }
}

/// the entropy associated to mnemonics. This is a bytes representation of the
/// mnemonics the user has to remember how to generate the root key of an
/// HD Wallet.
///
/// TODO: interface to generate a new entropy
///
/// # Security considerations
///
/// * do not store this value without encrypting it;
/// * do not leak the mnemonics;
/// * make sure the user remembers the mnemonics string;
///
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entropy(bip39::Entropy);
#[wasm_bindgen]
impl Entropy {
    /// retrieve the initial entropy of a wallet from the given
    /// english mnemonics.
    pub fn from_english_mnemonics(mnemonics: &str) -> Result<Entropy, JsValue> {
        Self::from_mnemonics(&bip39::dictionary::ENGLISH, mnemonics)
    }
    pub fn to_english_mnemonics(&self) -> String {
        self.to_mnemonics(&bip39::dictionary::ENGLISH)
    }
    pub fn to_array(&self) -> Result<JsValue, JsValue> {
        JsValue::from_serde(&self.0.as_ref()).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }
}
impl Entropy {
    fn from_mnemonics<D: bip39::dictionary::Language>(
        dic: &D,
        mnemonics: &str,
    ) -> Result<Entropy, JsValue> {
        let mnemonics = bip39::Mnemonics::from_string(dic, mnemonics)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
        bip39::Entropy::from_mnemonics(&mnemonics)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(Entropy)
    }
    fn to_mnemonics<D: bip39::dictionary::Language>(&self, dic: &D) -> String {
        format!("{}", self.0.to_mnemonics().to_string(dic))
    }
}

/* ************************************************************************* *
 *                          Low level Key management                         *
 * ************************************************************************* *
 *
 * Manage keys by hand. If you don't know what you are doing, prefer to use
 * BIP44 style wallets instead.
 */

/// A given private key. You can use this key to sign transactions.
///
/// # security considerations
///
/// * do not store this key without encrypting it;
/// * if leaked anyone can _spend_ a UTxO (Unspent Transaction Output)
///   with it;
///
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateKey(hdwallet::XPrv);
#[wasm_bindgen]
impl PrivateKey {
    /// create a new private key from a given Entropy
    pub fn new(entropy: &Entropy, password: &str) -> PrivateKey {
        let mut bytes = [0; hdwallet::XPRV_SIZE];
        wallet::keygen::generate_seed(&entropy.0, password.as_bytes(), &mut bytes);
        PrivateKey(hdwallet::XPrv::normalize_bytes(bytes))
    }

    /// retrieve a private key from the given hexadecimal string
    pub fn from_hex(hex: &str) -> Result<PrivateKey, JsValue> {
        use std::str::FromStr;
        hdwallet::XPrv::from_str(hex)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(PrivateKey)
    }
    /// convert the private key to an hexadecimal string
    pub fn to_hex(&self) -> String {
        format!("{}", self.0)
    }

    /// get the public key associated to this private key
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.public())
    }

    /// sign some bytes with this private key
    pub fn sign(&self, data: &[u8]) -> Signature {
        let signature = self.0.sign(data);
        Signature(signature)
    }

    /// derive this private key with the given index.
    ///
    /// # Security considerations
    ///
    /// * prefer the use of DerivationScheme::v2 when possible;
    /// * hard derivation index cannot be soft derived with the public key
    ///
    /// # Hard derivation vs Soft derivation
    ///
    /// If you pass an index below 0x80000000 then it is a soft derivation.
    /// The advantage of soft derivation is that it is possible to derive the
    /// public key too. I.e. derivation the private key with a soft derivation
    /// index and then retrieving the associated public key is equivalent to
    /// deriving the public key associated to the parent private key.
    ///
    /// Hard derivation index does not allow public key derivation.
    ///
    /// This is why deriving the private key should not fail while deriving
    /// the public key may fail (if the derivation index is invalid).
    ///
    pub fn derive(&self, derivation_scheme: DerivationScheme, index: u32) -> PrivateKey {
        PrivateKey(self.0.derive(derivation_scheme.0, index))
    }
}

/// The public key associated to a given private key.
///
/// It is not possible to sign (and then spend) with a private key.
/// However it is possible to verify a Signature.
///
/// # Security Consideration
///
/// * it is rather harmless to leak a public key, in the worst case
///   only the privacy is leaked;
///
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(hdwallet::XPub);
#[wasm_bindgen]
impl PublicKey {
    pub fn from_hex(hex: &str) -> Result<PublicKey, JsValue> {
        use std::str::FromStr;
        hdwallet::XPub::from_str(hex)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(PublicKey)
    }
    pub fn to_hex(&self) -> String {
        format!("{}", self.0)
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        self.0.verify(data, &signature.0)
    }

    /// derive this public key with the given index.
    ///
    /// # Errors
    ///
    /// If the index is not a soft derivation index (< 0x80000000) then
    /// calling this method will fail.
    ///
    /// # Security considerations
    ///
    /// * prefer the use of DerivationScheme::v2 when possible;
    /// * hard derivation index cannot be soft derived with the public key
    ///
    /// # Hard derivation vs Soft derivation
    ///
    /// If you pass an index below 0x80000000 then it is a soft derivation.
    /// The advantage of soft derivation is that it is possible to derive the
    /// public key too. I.e. derivation the private key with a soft derivation
    /// index and then retrieving the associated public key is equivalent to
    /// deriving the public key associated to the parent private key.
    ///
    /// Hard derivation index does not allow public key derivation.
    ///
    /// This is why deriving the private key should not fail while deriving
    /// the public key may fail (if the derivation index is invalid).
    ///
    pub fn derive(
        &self,
        derivation_scheme: DerivationScheme,
        index: u32,
    ) -> Result<PublicKey, JsValue> {
        self.0
            .derive(derivation_scheme.0, index)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(PublicKey)
    }

    /// get the bootstrap era address. I.E. this is an address without
    /// stake delegation.
    pub fn bootstrap_era_address(&self, blockchain_settings: &BlockchainSettings) -> Address {
        Address(address::ExtendedAddr::new_simple(
            self.0.clone(),
            blockchain_settings.protocol_magic.into(),
        ))
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Address(address::ExtendedAddr);
#[wasm_bindgen]
impl Address {
    pub fn to_base58(&self) -> String {
        format!("{}", self.0)
    }
    pub fn from_base58(s: &str) -> Result<Address, JsValue> {
        use std::str::FromStr;
        address::ExtendedAddr::from_str(s)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(Address)
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(hdwallet::Signature<()>);
#[wasm_bindgen]
impl Signature {
    pub fn from_hex(hex: &str) -> Result<Signature, JsValue> {
        hdwallet::Signature::from_hex(hex)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(Signature)
    }
    pub fn to_hex(&self) -> String {
        format!("{}", self.0)
    }
}

/* ************************************************************************* *
 *                     BIP44 style Wallet (Icarus/Yoroi/Rust)                *
 * ************************************************************************* *
 *
 * Manage BIP44 Style wallet. This is the preferred way to create new wallet
 * as it provides stronger security guarantees and is more flexible.
 */

#[wasm_bindgen]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AccountIndex(u32);
#[wasm_bindgen]
impl AccountIndex {
    pub fn new(index: u32) -> Result<AccountIndex, JsValue> {
        if index < bip44::BIP44_SOFT_UPPER_BOUND {
            Err(JsValue::from(
                "index out of bound. Expected value between 0x80000000 and 0xFFFFFFFF",
            ))
        } else {
            Ok(AccountIndex(index))
        }
    }
}
#[wasm_bindgen]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AddressKeyIndex(u32);
#[wasm_bindgen]
impl AddressKeyIndex {
    pub fn new(index: u32) -> Result<AddressKeyIndex, JsValue> {
        if index >= bip44::BIP44_SOFT_UPPER_BOUND {
            Err(JsValue::from(
                "index out of bound. Expected value between 0 and 0x80000000",
            ))
        } else {
            Ok(AddressKeyIndex(index))
        }
    }
}

/// Root Private Key of a BIP44 HD Wallet
#[wasm_bindgen]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip44RootPrivateKey {
    key: PrivateKey,
    derivation_scheme: DerivationScheme,
}
#[wasm_bindgen]
impl Bip44RootPrivateKey {
    pub fn new(key: PrivateKey, derivation_scheme: DerivationScheme) -> Bip44RootPrivateKey {
        Bip44RootPrivateKey {
            key: key,
            derivation_scheme: derivation_scheme,
        }
    }

    /// recover a wallet from the given mnemonic words and the given password
    ///
    /// To recover an icarus wallet:
    /// * 15 mnemonic words;
    /// * empty password;
    ///
    pub fn recover(entropy: &Entropy, password: &str) -> Result<Bip44RootPrivateKey, JsValue> {
        let key = PrivateKey::new(entropy, password);

        let rpk = Bip44RootPrivateKey {
            key: key,
            derivation_scheme: DerivationScheme::v2(),
        };

        Ok(rpk)
    }

    pub fn bip44_account(&self, index: AccountIndex) -> Bip44AccountPrivate {
        Bip44AccountPrivate {
            key: self
                .key
                .derive(self.derivation_scheme, bip44::BIP44_PURPOSE)
                .derive(self.derivation_scheme, bip44::BIP44_COIN_TYPE)
                .derive(self.derivation_scheme, index.0),
            derivation_scheme: self.derivation_scheme,
        }
    }

    pub fn key(&self) -> PrivateKey {
        self.key.clone()
    }
}

#[wasm_bindgen]
pub struct Bip44AccountPrivate {
    key: PrivateKey,
    derivation_scheme: DerivationScheme,
}
#[wasm_bindgen]
impl Bip44AccountPrivate {
    pub fn new(key: PrivateKey, derivation_scheme: DerivationScheme) -> Bip44AccountPrivate {
        Bip44AccountPrivate {
            key: key,
            derivation_scheme: derivation_scheme,
        }
    }
    pub fn public(&self) -> Bip44AccountPublic {
        Bip44AccountPublic {
            key: self.key.public(),
            derivation_scheme: self.derivation_scheme,
        }
    }
    pub fn address_key(&self, internal: bool, index: AddressKeyIndex) -> PrivateKey {
        self.key
            .derive(self.derivation_scheme, if internal { 1 } else { 0 })
            .derive(self.derivation_scheme, index.0)
    }

    pub fn key(&self) -> PrivateKey {
        self.key.clone()
    }
}

#[wasm_bindgen]
pub struct Bip44AccountPublic {
    key: PublicKey,
    derivation_scheme: DerivationScheme,
}
#[wasm_bindgen]
impl Bip44AccountPublic {
    pub fn new(key: PublicKey, derivation_scheme: DerivationScheme) -> Bip44AccountPublic {
        Bip44AccountPublic {
            key: key,
            derivation_scheme: derivation_scheme,
        }
    }
    pub fn address_key(
        &self,
        internal: bool,
        index: AddressKeyIndex,
    ) -> Result<PublicKey, JsValue> {
        self.key
            .derive(self.derivation_scheme, if internal { 1 } else { 0 })?
            .derive(self.derivation_scheme, index.0)
    }

    pub fn key(&self) -> PublicKey {
        self.key.clone()
    }
}

/* ************************************************************************* *
 *                     Daedalus Wallet Compatibility                         *
 * ************************************************************************* *
 *
 * Provide tooling for compatibility with Daedalus wallets. If you are creating
 * a new wallet, prefer Bip44 way.
 */

#[wasm_bindgen]
pub struct DaedalusWallet(PrivateKey);
#[wasm_bindgen]
impl DaedalusWallet {
    pub fn recover(entropy: &Entropy) -> Result<DaedalusWallet, JsValue> {
        let entropy_bytes = cbor_event::Value::Bytes(Vec::from(entropy.0.as_ref()));
        let entropy_cbor =
            cbor!(&entropy_bytes).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
        let seed: Vec<u8> = {
            use cryptoxide::digest::Digest;
            let mut blake2b = cryptoxide::blake2b::Blake2b::new(32);
            blake2b.input(&entropy_cbor);
            let mut out = [0; 32];
            blake2b.result(&mut out);
            let mut se = cbor_event::se::Serializer::new_vec();
            se.write_bytes(&Vec::from(&out[..]))
                .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
            se.finalize()
        };

        let key = PrivateKey(hdwallet::XPrv::generate_from_daedalus_seed(&seed));

        let rpk = DaedalusWallet(key);
        Ok(rpk)
    }
}

#[wasm_bindgen]
pub struct DaedalusAddressChecker {
    wallet: PrivateKey,
    payload_key: hdpayload::HDKey,
}
#[wasm_bindgen]
impl DaedalusAddressChecker {
    /// create a new address checker for the given daedalus address
    pub fn new(wallet: &DaedalusWallet) -> Self {
        let wallet = wallet.0.clone();
        let payload_key = hdpayload::HDKey::new(&wallet.0.public());
        DaedalusAddressChecker {
            wallet,
            payload_key,
        }
    }

    /// check that we own the given address.
    ///
    /// This is only possible like this because some payload is embedded in the
    /// address that only our wallet can decode. Once decoded we can retrieve
    /// the associated private key.
    ///
    /// The return private key is the key needed to sign the transaction to unlock
    /// UTxO associated to the address.
    pub fn check_address(&self, address: &Address) -> DaedalusCheckedAddress {
        if let Some(hdpa) = &address.0.attributes.derivation_path.clone() {
            if let Ok(path) = self.payload_key.decrypt_path(hdpa) {
                let mut key = self.wallet.clone();
                for index in path.iter() {
                    key = key.derive(DerivationScheme::v1(), *index);
                }
                return DaedalusCheckedAddress(Some(key));
            }
        }

        DaedalusCheckedAddress(None)
    }
}

/// result value of the check_address function of the DaedalusAddressChecker.
///
/// If the address passed to check_address was recognised by the daedalus wallet
/// then this object will contain the private key associated to this wallet
/// private key necessary to sign transactions
#[wasm_bindgen]
pub struct DaedalusCheckedAddress(Option<PrivateKey>);
#[wasm_bindgen]
impl DaedalusCheckedAddress {
    /// return if the value contains the private key (i.e. the check_address
    /// recognised an address).
    pub fn is_checked(&self) -> bool {
        self.0.is_some()
    }

    pub fn private_key(&self) -> Result<PrivateKey, JsValue> {
        match &self.0 {
            None => Err(JsValue::from_str(&format!("Daedalus Address didn't check"))),
            Some(ref sk) => Ok(sk.clone()),
        }
    }
}

/* ************************************************************************* *
 *                          Transaction Builder                              *
 * ************************************************************************* *
 *
 * New transaction build engine
 */

#[wasm_bindgen]
pub struct CoinDiff(coin::CoinDiff);
#[wasm_bindgen]
impl CoinDiff {
    pub fn is_zero(&self) -> bool {
        match self.0 {
            coin::CoinDiff::Zero => true,
            _ => false,
        }
    }
    pub fn is_negative(&self) -> bool {
        match self.0 {
            coin::CoinDiff::Negative(_) => true,
            _ => false,
        }
    }
    pub fn is_positive(&self) -> bool {
        match self.0 {
            coin::CoinDiff::Positive(_) => true,
            _ => false,
        }
    }

    pub fn value(&self) -> Coin {
        match self.0 {
            coin::CoinDiff::Positive(coin) => Coin(coin),
            coin::CoinDiff::Zero => Coin::new(),
            coin::CoinDiff::Negative(coin) => Coin(coin),
        }
    }
}

#[wasm_bindgen]
#[derive(Copy, Clone)]
pub struct Coin(coin::Coin);
impl serde::Serialize for Coin {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let v: u64 = *self.0;
        serializer.serialize_str(&format!("{}", v))
    }
}
struct CoinVisitor();
impl<'de> serde::de::Visitor<'de> for CoinVisitor {
    type Value = Coin;

    fn expecting(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "Lovelace Ada")
    }

    fn visit_str<'a, E>(self, v: &'a str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let i: u64 = match v.parse::<u64>() {
            Ok(v) => v,
            Err(err) => return Err(E::custom(format!("{:?}", err))),
        };
        match coin::Coin::new(i) {
            Err(err) => Err(E::custom(format!("{}", err))),
            Ok(h) => Ok(Coin(h)),
        }
    }
}
impl<'de> serde::Deserialize<'de> for Coin {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(CoinVisitor())
    }
}
#[wasm_bindgen]
impl Coin {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Coin {
        Coin(coin::Coin::zero())
    }

    pub fn from_str(s: &str) -> Result<Coin, JsValue> {
        s.parse()
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(Coin)
    }

    pub fn to_str(&self) -> String {
        format!("{}", self.0)
    }

    pub fn from(ada: u32, lovelace: u32) -> Result<Coin, JsValue> {
        let value = (ada as u64 * 1_000_000) + (lovelace as u64);
        coin::Coin::new(value)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(Coin)
    }

    pub fn ada(&self) -> u32 {
        let v = *self.0 / 1_000_000;
        assert!(v < 0xFFFF_FFFF);
        v as u32
    }

    pub fn lovelace(&self) -> u32 {
        (*self.0 % 1_000_000) as u32
    }

    pub fn add(&self, other: &Coin) -> Result<Coin, JsValue> {
        use std::ops::Add;
        self.0
            .add(other.0)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(Coin)
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct TransactionId(tx::TxId);
impl TransactionId {
    pub fn to_hex(&self) -> String {
        format!("{}", self.0)
    }
    pub fn from_hex(s: &str) -> Result<TransactionId, JsValue> {
        use std::str::FromStr;
        hash::Blake2b256::from_str(s)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(TransactionId)
    }
    fn convert(&self) -> tx::TxId {
        self.0.clone()
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct TxoPointer {
    id: TransactionId,
    index: u32,
}
#[wasm_bindgen]
impl TxoPointer {
    /// serialize into a JsValue object
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        JsValue::from_serde(self).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    /// retrieve the object from a JsValue.
    pub fn from_json(value: JsValue) -> Result<TxoPointer, JsValue> {
        value
            .into_serde()
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }
}
impl TxoPointer {
    fn convert(&self) -> tx::TxoPointer {
        tx::TxoPointer {
            id: self.id.convert(),
            index: self.index,
        }
    }
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone)]
pub struct TxOut {
    address: Address,
    value: Coin,
}
#[wasm_bindgen]
impl TxOut {
    /// serialize into a JsValue object
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        JsValue::from_serde(self).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    /// retrieve the object from a JsValue.
    pub fn from_json(value: JsValue) -> Result<TxOut, JsValue> {
        value
            .into_serde()
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }
}
impl TxOut {
    fn convert(&self) -> tx::TxOut {
        tx::TxOut {
            address: self.address.0.clone(),
            value: self.value.0,
        }
    }
}

/// a transaction type, this is not ready for sending to the network. It is only an
/// intermediate type to use between the transaction builder and the transaction
/// finalizer. It allows separation of concerns:
///
/// 1. build the transaction on one side/thread/machine/...;
/// 2. sign the transaction on the other/thread/machines/cold-wallet...;
///
#[wasm_bindgen]
pub struct Transaction(tx::Tx);
#[wasm_bindgen]
impl Transaction {
    pub fn id(&self) -> String {
        format!("{}", self.0.id())
    }
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        JsValue::from_serde(&self.0).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }
    pub fn to_hex(&self) -> Result<String, JsValue> {
        let bytes = cbor!(&self.0).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
        Ok(util::hex::encode(&bytes))
    }
    pub fn to_base58(&self) -> Result<String, JsValue> {
        let bytes = cbor!(&self.0).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
        Ok(util::base58::encode(&bytes))
    }
}

/// a signed transaction, ready to be sent to the network.
#[wasm_bindgen]
pub struct SignedTransaction(tx::TxAux);
#[wasm_bindgen]
impl SignedTransaction {
    pub fn id(&self) -> String {
        format!("{}", self.0.tx.id())
    }
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        JsValue::from_serde(&self.0).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }
    pub fn to_hex(&self) -> Result<String, JsValue> {
        let bytes = cbor!(&self.0).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
        Ok(util::hex::encode(&bytes))
    }
    pub fn to_base58(&self) -> Result<String, JsValue> {
        let bytes = cbor!(&self.0).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
        Ok(util::base58::encode(&bytes))
    }
}

/// This is the linear fee algorithm used buy the current cardano blockchain.
///
/// However it is possible the linear fee algorithm may change its settings:
///
/// It is currently a function `fee(n) = a * x + b`. `a` and `b` can be
/// re-configured by a protocol update. Users of this object need to be aware
/// that it may change and that they might need to update its settings.
///
#[wasm_bindgen]
pub struct LinearFeeAlgorithm(fee::LinearFee);
#[wasm_bindgen]
impl LinearFeeAlgorithm {
    /// this is the default mainnet linear fee algorithm. It is also known to work
    /// with the staging network and the current testnet.
    ///
    pub fn default() -> LinearFeeAlgorithm {
        LinearFeeAlgorithm(fee::LinearFee::default())
    }
}

/// This is the Output policy for automatic Input selection.
#[wasm_bindgen]
pub struct OutputPolicy(txutils::OutputPolicy);
#[wasm_bindgen]
impl OutputPolicy {
    /// requires to send back all the spare changes to only one given address
    pub fn change_to_one_address(address: Address) -> OutputPolicy {
        OutputPolicy(txutils::OutputPolicy::One(address.0))
    }
}

/// The transaction builder provides a set of tools to help build
/// a valid Transaction.
#[wasm_bindgen]
pub struct TransactionBuilder(txbuild::TxBuilder);
#[wasm_bindgen]
impl TransactionBuilder {
    /// create a new transaction builder
    #[wasm_bindgen(constructor)]
    pub fn new() -> TransactionBuilder {
        TransactionBuilder(txbuild::TxBuilder::new())
    }

    pub fn add_input(&mut self, txo_pointer: &TxoPointer, value: Coin) -> Result<(), JsValue> {
        self.0.add_input(&txo_pointer.convert(), value.0);
        Ok(())
    }

    pub fn get_input_total(&self) -> Result<Coin, JsValue> {
        self.0
            .get_input_total()
            .map(Coin)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    pub fn add_output(&mut self, output: &TxOut) -> Result<(), JsValue> {
        self.0.add_output_value(&output.convert());
        Ok(())
    }

    pub fn apply_output_policy(
        &mut self,
        fee_algorithm: &LinearFeeAlgorithm,
        policy: &OutputPolicy,
    ) -> Result<JsValue, JsValue> {
        self.0
            .add_output_policy(&fee_algorithm.0, &policy.0)
            .map(|all_txout| {
                all_txout
                    .into_iter()
                    .map(|txout| TxOut {
                        address: Address(txout.address),
                        value: Coin(txout.value),
                    })
                    .collect::<Vec<_>>()
            })
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .and_then(|v| {
                JsValue::from_serde(&v).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            })
    }

    pub fn get_output_total(&self) -> Result<Coin, JsValue> {
        self.0
            .get_output_total()
            .map(Coin)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    pub fn estimate_fee(&self, fee_algorithm: &LinearFeeAlgorithm) -> Result<Coin, JsValue> {
        self.0
            .calculate_fee(&fee_algorithm.0)
            .map(|fee| Coin(fee.to_coin()))
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    pub fn get_balance(&self, fee_algorithm: &LinearFeeAlgorithm) -> Result<CoinDiff, JsValue> {
        self.0
            .balance(&fee_algorithm.0)
            .map(CoinDiff)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    pub fn get_balance_without_fees(&self) -> Result<CoinDiff, JsValue> {
        self.0
            .balance_without_fees()
            .map(CoinDiff)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    pub fn make_transaction(self) -> Result<Transaction, JsValue> {
        self.0
            .make_tx()
            .map(Transaction)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }
}

#[wasm_bindgen]
pub struct TransactionFinalized {
    tx_id: tx::TxId,
    finalized: txbuild::TxFinalized,
}
#[wasm_bindgen]
impl TransactionFinalized {
    #[wasm_bindgen(constructor)]
    pub fn new(transaction: Transaction) -> TransactionFinalized {
        TransactionFinalized {
            tx_id: transaction.0.id(),
            finalized: txbuild::TxFinalized::new(transaction.0),
        }
    }

    /// sign the inputs of the transaction (i.e. unlock the funds the input are
    /// referring to).
    ///
    /// The signature must be added one by one in the same order the inputs have
    /// been added.
    pub fn sign(
        &mut self,
        blockchain_settings: &BlockchainSettings,
        key: &PrivateKey,
    ) -> Result<(), JsValue> {
        let signature = tx::TxInWitness::new_extended_pk(
            blockchain_settings.protocol_magic,
            &key.0,
            &self.tx_id,
        );
        self.finalized
            .add_witness(signature)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    pub fn finalize(self) -> Result<SignedTransaction, JsValue> {
        self.finalized
            .make_txaux()
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(SignedTransaction)
    }
}

/* ************************************************************************* *
 *                         Redemption keys                                   *
 * ************************************************************************* *
 *
 * Retrieve the redemption keys and redeem to a given address
 */

use self::cardano::redeem;

#[wasm_bindgen]
pub struct PrivateRedeemKey(redeem::PrivateKey);
#[wasm_bindgen]
impl PrivateRedeemKey {
    /// retrieve the private redeeming key from the given bytes (expect 64 bytes)
    pub fn from_bytes(bytes: &[u8]) -> Result<PrivateRedeemKey, JsValue> {
        redeem::PrivateKey::from_slice(bytes)
            .map_err(|e| JsValue::from_str(&format! {"{}", e}))
            .map(PrivateRedeemKey)
    }

    /// retrieve a private key from the given hexadecimal string
    pub fn from_hex(hex: &str) -> Result<PrivateRedeemKey, JsValue> {
        redeem::PrivateKey::from_hex(hex)
            .map_err(|e| JsValue::from_str(&format! {"{}", e}))
            .map(PrivateRedeemKey)
    }
    /// convert the private key to an hexadecimal string
    pub fn to_hex(&self) -> String {
        format!("{}", self.0)
    }

    /// get the public key associated to this private key
    pub fn public(&self) -> PublicRedeemKey {
        PublicRedeemKey(self.0.public())
    }

    /// sign some bytes with this private key
    pub fn sign(&self, data: &[u8]) -> RedeemSignature {
        let signature = self.0.sign(data);
        RedeemSignature(signature)
    }
}

#[wasm_bindgen]
pub struct PublicRedeemKey(redeem::PublicKey);
#[wasm_bindgen]
impl PublicRedeemKey {
    /// retrieve a public key from the given hexadecimal string
    pub fn from_hex(hex: &str) -> Result<PublicRedeemKey, JsValue> {
        redeem::PublicKey::from_hex(hex)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(PublicRedeemKey)
    }
    /// convert the public key to an hexadecimal string
    pub fn to_hex(&self) -> String {
        format!("{}", self.0)
    }

    /// verify the signature with the given public key
    pub fn verify(&self, data: &[u8], signature: &RedeemSignature) -> bool {
        self.0.verify(&signature.0, data)
    }

    /// generate the address for this redeeming key
    pub fn address(&self, settings: &BlockchainSettings) -> Address {
        let address_type = address::AddrType::ATRedeem;
        let spending_data = address::SpendingData::RedeemASD(self.0.clone());
        let attributes =
            address::Attributes::new_bootstrap_era(None, settings.protocol_magic.into());
        Address(address::ExtendedAddr::new(
            address_type,
            spending_data,
            attributes,
        ))
    }
}

#[wasm_bindgen]
pub struct RedeemSignature(redeem::Signature);
#[wasm_bindgen]
impl RedeemSignature {
    pub fn from_hex(hex: &str) -> Result<RedeemSignature, JsValue> {
        redeem::Signature::from_hex(hex)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(RedeemSignature)
    }
    pub fn to_hex(&self) -> String {
        format!("{}", self.0)
    }
}

/* ************************************************************************* *
 *                          Paper wallet scrambling                          *
 * ************************************************************************* *
 *
 * the API for the paper wallet
 */

#[wasm_bindgen]
pub fn paper_wallet_scramble(
    entropy: &Entropy,
    iv: &[u8],
    password: &str,
) -> Result<JsValue, JsValue> {
    if iv.len() != paperwallet::IV_SIZE {
        return Err(JsValue::from_str(&format!(
            "Invalid IV size, expected 8 random bytes but received {} bytes",
            iv.len(),
        )));
    }

    let bytes = paperwallet::scramble(iv, password.as_bytes(), entropy.0.as_ref());

    JsValue::from_serde(&bytes).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
}

#[wasm_bindgen]
pub fn paper_wallet_unscramble(paper: &[u8], password: &str) -> Result<Entropy, JsValue> {
    if paper.len() <= paperwallet::IV_SIZE {
        return Err(JsValue::from_str(&format!(
            "Not enough data to decode the paper wallet, expecting at least 8 bytes but received {} bytes",
            paper.len(),
        )));
    }
    let bytes = paperwallet::unscramble(password.as_bytes(), paper);

    bip39::Entropy::from_slice(&bytes)
        .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
        .map(Entropy)
}

/* ************************************************************************* *
 *                          Password Encrypted Data                          *
 * ************************************************************************* *
 *
 * provide a function with strong enough parameter to encrypt data in a safe
 * and secure manner.
 */

mod password_encryption_parameter {
    pub const ITER: u32 = 19_162;
    pub const SALT_SIZE: usize = 32;
    pub const NONCE_SIZE: usize = 12;
    pub const KEY_SIZE: usize = 32;
    pub const TAG_SIZE: usize = 16;

    pub const METADATA_SIZE: usize = SALT_SIZE + NONCE_SIZE + TAG_SIZE;

    pub const SALT_START: usize = 0;
    pub const SALT_END: usize = SALT_START + SALT_SIZE;
    pub const NONCE_START: usize = SALT_END;
    pub const NONCE_END: usize = NONCE_START + NONCE_SIZE;
    pub const TAG_START: usize = NONCE_END;
    pub const TAG_END: usize = TAG_START + TAG_SIZE;
    pub const ENCRYPTED_START: usize = TAG_END;
}

/// encrypt the given data with a password, a salt and a nonce
///
/// Salt: must be 32 bytes long;
/// Nonce: must be 12 bytes long;
///
#[wasm_bindgen]
pub fn password_encrypt(
    password: &str,
    salt: &[u8],
    nonce: &[u8],
    data: &[u8],
) -> Result<JsValue, JsValue> {
    let password = password.as_bytes();
    if salt.len() != password_encryption_parameter::SALT_SIZE {
        return Err(JsValue::from("Invalid Salt Size, expected 32 bytes"));
    }
    if nonce.len() != password_encryption_parameter::NONCE_SIZE {
        return Err(JsValue::from("Invalid Nonce Size, expected 12 bytes"));
    }

    let key = {
        let mut mac = Hmac::new(Sha512::new(), &password);
        let mut key = [0u8; password_encryption_parameter::KEY_SIZE];
        pbkdf2(
            &mut mac,
            &salt[..],
            password_encryption_parameter::ITER,
            &mut key,
        );
        key
    };

    let mut tag = [0u8; password_encryption_parameter::TAG_SIZE];
    let mut encrypted: Vec<u8> = std::iter::repeat(0).take(data.len()).collect();
    {
        ChaCha20Poly1305::new(&key, &nonce, &[]).encrypt(&data, &mut encrypted, &mut tag);
    }

    let mut output = Vec::with_capacity(data.len() + password_encryption_parameter::METADATA_SIZE);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&tag);
    output.extend_from_slice(&encrypted);

    JsValue::from_serde(&output).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
}

/// decrypt the data with the password
///
#[wasm_bindgen]
pub fn password_decrypt(password: &str, encrypted_data: &[u8]) -> Result<JsValue, JsValue> {
    if encrypted_data.len() <= password_encryption_parameter::METADATA_SIZE {
        return Err(JsValue::from_str("Not enough data to decrypt"));
    }

    let password = password.as_bytes();
    let salt = &encrypted_data
        [password_encryption_parameter::SALT_START..password_encryption_parameter::SALT_END];
    let nonce = &encrypted_data
        [password_encryption_parameter::NONCE_START..password_encryption_parameter::NONCE_END];
    let tag = &encrypted_data
        [password_encryption_parameter::TAG_START..password_encryption_parameter::TAG_END];
    let encrypted = &encrypted_data[password_encryption_parameter::ENCRYPTED_START..];

    let key = {
        let mut mac = Hmac::new(Sha512::new(), &password);
        let mut key = [0u8; password_encryption_parameter::KEY_SIZE];
        pbkdf2(
            &mut mac,
            &salt[..],
            password_encryption_parameter::ITER,
            &mut key,
        );
        key
    };

    let mut decrypted: Vec<u8> = std::iter::repeat(0).take(encrypted.len()).collect();
    let decryption_succeed =
        { ChaCha20Poly1305::new(&key, &nonce, &[]).decrypt(&encrypted, &mut decrypted, &tag) };

    if decryption_succeed {
        JsValue::from_serde(&decrypted).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    } else {
        Err(JsValue::from_str("Cannot decrypt the data"))
    }
}

cfg_if! {
    // When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
    // allocator.
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}
