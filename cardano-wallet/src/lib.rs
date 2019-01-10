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
    coin, config, fee, hdwallet, tx, txbuild, txutils, util, wallet,
};

/// setting of the blockchain
///
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct BlockchainSettings {
    /// code of a specific blockchain used to sign transactions and blocks
    protocol_magic: config::ProtocolMagic,
}
#[wasm_bindgen]
impl BlockchainSettings {
    pub fn to_json(&self) -> Result<JsValue, JsValue> {
        JsValue::from_serde(self).map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }
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
#[derive(Copy, Clone)]
pub struct DerivationScheme(hdwallet::DerivationScheme);
#[wasm_bindgen]
impl DerivationScheme {
    /// deprecated, provided here only for backward compatibility with
    /// Daedalus' addresses
    pub fn v1() -> DerivationScheme {
        DerivationScheme(hdwallet::DerivationScheme::V1)
    }

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
pub struct Entropy(bip39::Entropy);
#[wasm_bindgen]
impl Entropy {
    pub fn from_english_mnemonics(mnemonics: &str) -> Result<Entropy, JsValue> {
        Self::from_mnemonics(&bip39::dictionary::ENGLISH, mnemonics)
    }
    pub fn to_english_mnemonics(&self) -> String {
        self.to_mnemonics(&bip39::dictionary::ENGLISH)
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
pub struct PrivateKey(hdwallet::XPrv);
#[wasm_bindgen]
impl PrivateKey {
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
pub struct Address(address::ExtendedAddr);
#[wasm_bindgen]
impl Address {
    pub fn to_hex(&self) -> String {
        format!("{}", self.0)
    }
    pub fn from_hex(s: &str) -> Result<Address, JsValue> {
        use std::str::FromStr;
        address::ExtendedAddr::from_str(s)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
            .map(Address)
    }
}

#[wasm_bindgen]
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
        let mut bytes = [0; hdwallet::XPRV_SIZE];
        wallet::keygen::generate_seed(&entropy.0, password.as_bytes(), &mut bytes);
        let key = PrivateKey(hdwallet::XPrv::normalize_bytes(bytes));

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
    pub fn recover(mnemonics: &str) -> Result<DaedalusWallet, JsValue> {
        let mnemonics = bip39::Mnemonics::from_string(&bip39::dictionary::ENGLISH, mnemonics)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
        let entropy = bip39::Entropy::from_mnemonics(&mnemonics)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
        let entropy_bytes = cbor_event::Value::Bytes(Vec::from(entropy.as_ref()));
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct TxoPointer {
    id: tx::TxId,
    index: u32,
}
impl TxoPointer {
    fn convert(&self) -> tx::TxoPointer {
        tx::TxoPointer {
            id: self.id,
            index: self.index,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct TxOut {
    address: address::ExtendedAddr,
    value: Coin,
}
impl TxOut {
    fn convert(&self) -> tx::TxOut {
        tx::TxOut {
            address: self.address.clone(),
            value: self.value.0,
        }
    }
}

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

#[wasm_bindgen]
pub struct LinearFeeAlgorithm(fee::LinearFee);
#[wasm_bindgen]
impl LinearFeeAlgorithm {
    pub fn default() -> LinearFeeAlgorithm {
        LinearFeeAlgorithm(fee::LinearFee::default())
    }
}

#[wasm_bindgen]
pub struct OutputPolicy(txutils::OutputPolicy);
#[wasm_bindgen]
impl OutputPolicy {
    pub fn change_to_one_address(address: Address) -> OutputPolicy {
        OutputPolicy(txutils::OutputPolicy::One(address.0))
    }
}

#[wasm_bindgen]
pub struct TransactionBuilder(txbuild::TxBuilder);
#[wasm_bindgen]
impl TransactionBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> TransactionBuilder {
        TransactionBuilder(txbuild::TxBuilder::new())
    }

    pub fn add_input(&mut self, input_ptr: &JsValue, value: Coin) -> Result<(), JsValue> {
        let txo_pointer: TxoPointer = input_ptr
            .into_serde()
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;

        self.0.add_input(&txo_pointer.convert(), value.0);
        Ok(())
    }

    pub fn get_input_total(&self) -> Result<Coin, JsValue> {
        self.0
            .get_input_total()
            .map(Coin)
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))
    }

    pub fn add_output(&mut self, output: &JsValue) -> Result<(), JsValue> {
        let output: TxOut = output
            .into_serde()
            .map_err(|e| JsValue::from_str(&format! {"{:?}", e}))?;
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
                        address: txout.address,
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
    pub fn new(transaction: Transaction) -> TransactionFinalized {
        TransactionFinalized {
            tx_id: transaction.0.id(),
            finalized: txbuild::TxFinalized::new(transaction.0),
        }
    }

    pub fn sign(
        &mut self,
        blockchain_settings: &BlockchainSettings,
        key: &PrivateKey,
    ) -> Result<(), JsValue> {
        let signature =
            tx::TxInWitness::new(blockchain_settings.protocol_magic, &key.0, &self.tx_id);
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
