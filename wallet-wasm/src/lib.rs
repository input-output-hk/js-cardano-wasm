extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate cardano;
extern crate cryptoxide;
extern crate serde_json;
#[macro_use]
extern crate cbor_event;

use self::cryptoxide::blake2b::Blake2b;
use self::cryptoxide::chacha20poly1305::ChaCha20Poly1305;
use self::cryptoxide::digest::Digest;
use self::cryptoxide::hmac::Hmac;
use self::cryptoxide::pbkdf2::pbkdf2;
use self::cryptoxide::sha2::{Sha256, Sha512};

use self::cardano::address;
use self::cardano::bip::bip39;
use self::cardano::config::Config;
use self::cardano::hdpayload;
use self::cardano::hdwallet;
use self::cardano::paperwallet;
use self::cardano::wallet::{
    self, bip44, rindex,
    scheme::{SelectionPolicy, Wallet},
};
use self::cardano::{coin, fee, tx, txutils, util::hex};
use self::cardano::{redeem, txbuild};

use self::cardano::util::try_from_slice::TryFromSlice;

use std::ffi::{CStr, CString};
use std::iter::repeat;
use std::os::raw::{c_char, c_uchar, c_uint, c_void};
use std::{convert, fmt, mem, result, string};
//use std::slice::{from_raw_parts};

// In order to work with the memory we expose (de)allocation methods
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut c_void {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    mem::forget(buf);
    return ptr as *mut c_void;
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut c_void, cap: usize) {
    unsafe {
        let _buf = Vec::from_raw_parts(ptr, 0, cap);
    }
}

#[no_mangle]
pub extern "C" fn dealloc_str(ptr: *mut c_char) {
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn pbkdf2_sha256(
    password: *mut c_char,
    salt: *mut c_char,
    iters: u32,
    output: u32,
) -> *mut c_char {
    unsafe {
        let salt = CStr::from_ptr(salt);
        let password = CStr::from_ptr(password);

        let salt = salt.to_bytes();
        let password = password.to_bytes();

        let mut mac = Hmac::new(Sha256::new(), &password[..]);
        let mut result: Vec<u8> = repeat(0).take(output as usize).collect();
        pbkdf2(&mut mac, &salt[..], iters, &mut result);
        let s = CString::new(result).unwrap();
        s.into_raw()
    }
}

unsafe fn read_data(data_ptr: *const c_uchar, sz: usize) -> Vec<u8> {
    let data_slice = std::slice::from_raw_parts(data_ptr, sz);
    let mut data = Vec::with_capacity(sz);
    data.extend_from_slice(data_slice);
    data
}

unsafe fn write_data(data: &[u8], data_ptr: *mut c_uchar) {
    let sz = data.len();
    let out = std::slice::from_raw_parts_mut(data_ptr, sz);
    out[0..sz].clone_from_slice(data)
}

unsafe fn read_data_u32(data_ptr: *const c_uint, sz: usize) -> Vec<u32> {
    let data_slice = std::slice::from_raw_parts(data_ptr, sz);
    let mut data = Vec::with_capacity(sz);
    data.extend_from_slice(data_slice);
    data
}

unsafe fn write_data_u32(data: &[u32], data_ptr: *mut c_uint) {
    let sz = data.len();
    let out = std::slice::from_raw_parts_mut(data_ptr, sz);
    out[0..sz].clone_from_slice(data)
}

unsafe fn read_xprv(xprv_ptr: *const c_uchar) -> hdwallet::XPrv {
    let xprv_slice = std::slice::from_raw_parts(xprv_ptr, hdwallet::XPRV_SIZE);
    let mut xprv_bytes = [0; hdwallet::XPRV_SIZE];
    xprv_bytes[..].clone_from_slice(xprv_slice);
    hdwallet::XPrv::from_bytes_verified(xprv_bytes).unwrap()
}

unsafe fn write_xprv(xprv: &hdwallet::XPrv, xprv_ptr: *mut c_uchar) {
    let out = std::slice::from_raw_parts_mut(xprv_ptr, hdwallet::XPRV_SIZE);
    out[0..hdwallet::XPRV_SIZE].clone_from_slice(xprv.as_ref());
}

unsafe fn read_xpub(xpub_ptr: *const c_uchar) -> hdwallet::XPub {
    let xpub_slice = std::slice::from_raw_parts(xpub_ptr, hdwallet::XPUB_SIZE);
    hdwallet::XPub::from_slice(xpub_slice).unwrap()
}

unsafe fn write_xpub(xpub: &hdwallet::XPub, xpub_ptr: *mut c_uchar) {
    let out = std::slice::from_raw_parts_mut(xpub_ptr, hdwallet::XPUB_SIZE);
    out[0..hdwallet::XPUB_SIZE].clone_from_slice(xpub.as_ref());
}

unsafe fn read_signature<T>(sig_ptr: *const c_uchar) -> hdwallet::Signature<T> {
    let signature_slice = std::slice::from_raw_parts(sig_ptr, hdwallet::SIGNATURE_SIZE);
    hdwallet::Signature::from_slice(signature_slice).unwrap()
}

unsafe fn write_signature<T>(signature: &hdwallet::Signature<T>, out_ptr: *mut c_uchar) {
    let out = std::slice::from_raw_parts_mut(out_ptr, hdwallet::SIGNATURE_SIZE);
    out[0..hdwallet::SIGNATURE_SIZE].clone_from_slice(signature.as_ref());
}

unsafe fn read_seed(seed_ptr: *const c_uchar) -> hdwallet::Seed {
    let seed_slice = std::slice::from_raw_parts(seed_ptr, hdwallet::SEED_SIZE);
    hdwallet::Seed::from_slice(seed_slice).unwrap()
}

#[no_mangle]
pub extern "C" fn wallet_from_enhanced_entropy(
    entropy_ptr: *const c_uchar,
    entropy_size: usize,
    password_ptr: *const c_uchar,
    password_size: usize,
    out: *mut c_uchar,
) -> usize {
    match entropy_size {
        16 | 20 | 24 | 28 | 32 => {}
        _ => return 1,
    }
    let entropy = unsafe { read_data(entropy_ptr, entropy_size) };
    let password = unsafe { read_data(password_ptr, password_size) };
    // it is okay to unwrap here, we already checked the size
    let entropy = bip39::Entropy::from_slice(&entropy).unwrap();
    let mut bytes = [0; hdwallet::XPRV_SIZE];
    wallet::keygen::generate_seed(&entropy, &password, &mut bytes);
    let xprv = hdwallet::XPrv::normalize_bytes(bytes);
    unsafe { write_xprv(&xprv, out) };
    0
}

#[no_mangle]
pub extern "C" fn wallet_from_seed(seed_ptr: *const c_uchar, out: *mut c_uchar) {
    let seed = unsafe { read_seed(seed_ptr) };
    let xprv = hdwallet::XPrv::generate_from_seed(&seed);
    unsafe { write_xprv(&xprv, out) }
}

#[no_mangle]
pub extern "C" fn wallet_from_daedalus_seed(seed_ptr: *const c_uchar, out: *mut c_uchar) {
    let seed = unsafe { read_seed(seed_ptr) };
    let seed = cbor!(seed.as_ref()).expect("to serialise cbor in memory");
    let xprv = hdwallet::XPrv::generate_from_daedalus_seed(&seed);
    unsafe { write_xprv(&xprv, out) }
}

#[no_mangle]
pub extern "C" fn wallet_to_public(xprv_ptr: *const c_uchar, out: *mut c_uchar) {
    let xprv = unsafe { read_xprv(xprv_ptr) };
    let xpub = xprv.public();
    unsafe { write_xpub(&xpub, out) }
}

#[no_mangle]
pub extern "C" fn wallet_derive_private(xprv_ptr: *const c_uchar, index: u32, out: *mut c_uchar) {
    let xprv = unsafe { read_xprv(xprv_ptr) };
    let child = xprv.derive(hdwallet::DerivationScheme::V2, index);
    unsafe { write_xprv(&child, out) }
}

#[no_mangle]
pub extern "C" fn wallet_derive_public(
    xpub_ptr: *const c_uchar,
    index: u32,
    out: *mut c_uchar,
) -> bool {
    let xpub = unsafe { read_xpub(xpub_ptr) };
    match xpub.derive(hdwallet::DerivationScheme::V2, index) {
        Ok(child) => {
            unsafe { write_xpub(&child, out) };
            true
        }
        Err(_) => false,
    }
}

#[no_mangle]
pub extern "C" fn wallet_sign(
    xprv_ptr: *const c_uchar,
    msg_ptr: *const c_uchar,
    msg_sz: usize,
    out: *mut c_uchar,
) {
    let xprv = unsafe { read_xprv(xprv_ptr) };
    let msg = unsafe { read_data(msg_ptr, msg_sz) };
    let signature: hdwallet::Signature<Vec<u8>> = xprv.sign(&msg[..]);
    unsafe { write_signature(&signature, out) }
}

#[no_mangle]
pub extern "C" fn wallet_verify(
    xpub_ptr: *const c_uchar,
    msg_ptr: *const c_uchar,
    msg_sz: usize,
    sig_ptr: *const c_uchar,
) -> bool {
    let xpub = unsafe { read_xpub(xpub_ptr) };
    let msg = unsafe { read_data(msg_ptr, msg_sz) };
    let signature = unsafe { read_signature::<Vec<u8>>(sig_ptr) };
    xpub.verify(&msg, &signature)
}

#[no_mangle]
pub extern "C" fn paper_scramble(
    iv_ptr: *const c_uchar,
    pass_ptr: *const c_uchar,
    pass_sz: usize,
    input_ptr: *const c_uchar,
    input_sz: usize,
    out: *mut c_uchar,
) {
    let iv = unsafe { read_data(iv_ptr, paperwallet::IV_SIZE) };
    let pass = unsafe { read_data(pass_ptr, pass_sz) };
    let input = unsafe { read_data(input_ptr, input_sz) };
    let output = paperwallet::scramble(&iv[..], &pass[..], &input[..]);
    unsafe { write_data(&output[..], out) }
}

#[no_mangle]
pub extern "C" fn paper_unscramble(
    pass_ptr: *const c_uchar,
    pass_sz: usize,
    input_ptr: *const c_uchar,
    input_sz: usize,
    out: *mut c_uchar,
) {
    let pass = unsafe { read_data(pass_ptr, pass_sz) };
    let input = unsafe { read_data(input_ptr, input_sz) };
    let output = paperwallet::unscramble(&pass[..], &input[..]);
    unsafe { write_data(&output[..], out) }
}

#[no_mangle]
pub extern "C" fn blake2b_256(msg_ptr: *const c_uchar, msg_sz: usize, out: *mut c_uchar) {
    let mut b2b = Blake2b::new(32);
    let mut outv = [0; 32];
    let msg = unsafe { read_data(msg_ptr, msg_sz) };
    b2b.input(&msg);
    b2b.result(&mut outv);
    unsafe { write_data(&outv, out) }
}

fn default_network_magic() -> cardano::config::NetworkMagic {
    cardano::config::ProtocolMagic::default().into()
}

#[no_mangle]
pub extern "C" fn wallet_public_to_address(
    xpub_ptr: *const c_uchar,
    payload_ptr: *const c_uchar,
    payload_sz: usize,
    out: *mut c_uchar,
) -> u32 {
    let xpub = unsafe { read_xpub(xpub_ptr) };
    let payload = unsafe { read_data(payload_ptr, payload_sz) };

    let hdap = hdpayload::HDAddressPayload::from_vec(payload);

    let addr_type = address::AddrType::ATPubKey;
    let sd = address::SpendingData::PubKeyASD(xpub.clone());
    let attrs = address::Attributes::new_bootstrap_era(Some(hdap), default_network_magic());
    let ea = address::ExtendedAddr::new(addr_type, sd, attrs);

    let ea_bytes = cbor!(ea).unwrap();

    unsafe { write_data(&ea_bytes, out) }

    return ea_bytes.len() as u32;
}

#[no_mangle]
pub extern "C" fn wallet_address_get_payload(
    addr_ptr: *const c_uchar,
    addr_sz: usize,
    out: *mut c_uchar,
) -> u32 {
    let addr_bytes = unsafe { read_data(addr_ptr, addr_sz) };
    match address::ExtendedAddr::try_from_slice(&addr_bytes).ok() {
        None => (-1i32) as u32,
        Some(r) => match r.attributes.derivation_path {
            None => 0,
            Some(dpath) => {
                unsafe { write_data(dpath.as_ref(), out) };
                dpath.as_ref().len() as u32
            }
        },
    }
}

#[no_mangle]
pub extern "C" fn wallet_payload_initiate(xpub_ptr: *const c_uchar, out: *mut c_uchar) {
    let xpub = unsafe { read_xpub(xpub_ptr) };
    let hdkey = hdpayload::HDKey::new(&xpub);
    unsafe {
        write_data(hdkey.as_ref(), out);
    }
}

#[no_mangle]
pub extern "C" fn wallet_payload_encrypt(
    key_ptr: *const c_uchar,
    path_array: *const c_uint,
    path_sz: usize,
    out: *mut c_uchar,
) -> u32 {
    let key_bytes = unsafe { read_data(key_ptr, hdpayload::HDKEY_SIZE) };
    let path_vec = unsafe { read_data_u32(path_array, path_sz) };
    let hdkey = hdpayload::HDKey::from_slice(&key_bytes).unwrap();

    let path = hdpayload::Path::new(path_vec);

    let payload = hdkey.encrypt_path(&path);

    unsafe { write_data(payload.as_ref(), out) };
    payload.len() as u32
}

#[no_mangle]
pub extern "C" fn wallet_payload_decrypt(
    key_ptr: *const c_uchar,
    payload_ptr: *const c_uchar,
    payload_sz: usize,
    out: *mut c_uint,
) -> u32 {
    let key_bytes = unsafe { read_data(key_ptr, hdpayload::HDKEY_SIZE) };
    let payload_bytes = unsafe { read_data(payload_ptr, payload_sz) };

    let hdkey = hdpayload::HDKey::from_slice(&key_bytes).unwrap();
    let payload = hdpayload::HDAddressPayload::from_bytes(&payload_bytes);

    match hdkey.decrypt_path(&payload) {
        Err(_) => 0xffffffff,
        Ok(path) => {
            let v = path.as_ref();
            unsafe { write_data_u32(v, out) };
            v.len() as u32
        }
    }
}

#[no_mangle]
pub extern "C" fn wallet_txin_create(
    txid_ptr: *const c_uchar,
    index: u32,
    out: *mut c_uchar,
) -> u32 {
    let txid_bytes = unsafe { read_data(txid_ptr, tx::TxId::HASH_SIZE) };

    let txid = tx::TxId::try_from_slice(&txid_bytes).unwrap();

    let txin = tx::TxoPointer::new(txid, index);
    let out_buf = cbor!(&txin).unwrap();

    unsafe { write_data(&out_buf, out) }
    out_buf.len() as u32
}

#[no_mangle]
pub extern "C" fn wallet_txout_create(
    ea_ptr: *const c_uchar,
    ea_sz: usize,
    amount: u32,
    out: *mut c_uchar,
) -> u32 {
    let ea_bytes = unsafe { read_data(ea_ptr, ea_sz) };

    let ea = address::ExtendedAddr::try_from_slice(&ea_bytes).unwrap();
    let coin = coin::Coin::new(amount as u64).unwrap();

    let txout = tx::TxOut::new(ea, coin);
    let out_buf = cbor!(&txout).unwrap();

    unsafe { write_data(&out_buf, out) }
    out_buf.len() as u32
}

#[no_mangle]
pub extern "C" fn wallet_tx_new(out: *mut c_uchar) -> u32 {
    let tx = tx::Tx::new();
    let out_buf = cbor!(&tx).unwrap();
    unsafe { write_data(&out_buf, out) }
    out_buf.len() as u32
}

#[no_mangle]
pub extern "C" fn wallet_tx_add_txin(
    tx_ptr: *const c_uchar,
    tx_sz: usize,
    txin_ptr: *const c_uchar,
    txin_sz: usize,
    out: *mut c_uchar,
) -> u32 {
    let tx_bytes = unsafe { read_data(tx_ptr, tx_sz) };
    let txin_bytes = unsafe { read_data(txin_ptr, txin_sz) };

    let mut deserialiser = cbor_event::de::Deserializer::from(tx_bytes.as_slice());
    let mut tx: tx::Tx = deserialiser.deserialize_complete().unwrap();
    deserialiser = cbor_event::de::Deserializer::from(txin_bytes.as_slice());
    let txin = deserialiser.deserialize_complete().unwrap();

    tx.add_input(txin);

    let out_buf = cbor!(&tx).unwrap();
    unsafe { write_data(&out_buf, out) }
    out_buf.len() as u32
}

#[no_mangle]
pub extern "C" fn wallet_tx_add_txout(
    tx_ptr: *const c_uchar,
    tx_sz: usize,
    txout_ptr: *const c_uchar,
    txout_sz: usize,
    out: *mut c_uchar,
) -> u32 {
    let tx_bytes = unsafe { read_data(tx_ptr, tx_sz) };
    let txout_bytes = unsafe { read_data(txout_ptr, txout_sz) };

    let mut deserialiser = cbor_event::de::Deserializer::from(tx_bytes.as_slice());
    let mut tx: tx::Tx = deserialiser.deserialize_complete().unwrap();
    deserialiser = cbor_event::de::Deserializer::from(txout_bytes.as_slice());
    let txout = deserialiser.deserialize_complete().unwrap();

    tx.add_output(txout);

    let out_buf = cbor!(&tx).unwrap();
    unsafe { write_data(&out_buf, out) }
    out_buf.len() as u32
}

#[no_mangle]
pub extern "C" fn wallet_tx_sign(
    cfg_ptr: *const c_uchar,
    cfg_size: usize,
    xprv_ptr: *const c_uchar,
    tx_ptr: *const c_uchar,
    tx_sz: usize,
    out: *mut c_uchar,
) {
    let cfg_bytes: Vec<u8> = unsafe { read_data(cfg_ptr, cfg_size) };
    let cfg_str = String::from_utf8(cfg_bytes).unwrap();
    let cfg: Config = serde_json::from_str(cfg_str.as_str()).unwrap();
    let xprv = unsafe { read_xprv(xprv_ptr) };
    let tx_bytes = unsafe { read_data(tx_ptr, tx_sz) };

    let mut deserialiser = cbor_event::de::Deserializer::from(tx_bytes.as_slice());
    let tx: tx::Tx = deserialiser.deserialize_complete().unwrap();

    let txinwitness = tx::TxInWitness::new(cfg.protocol_magic, &xprv, &tx.id());

    let signature = match txinwitness {
        tx::TxInWitness::PkWitness(_, sig) => sig,
        _ => unimplemented!(), // this should never happen as we are signing for the tx anyway
    };
    unsafe { write_signature(&signature, out) }
}

#[no_mangle]
pub extern "C" fn wallet_tx_verify(
    cfg_ptr: *const c_uchar,
    cfg_size: usize,
    xpub_ptr: *const c_uchar,
    tx_ptr: *const c_uchar,
    tx_sz: usize,
    sig_ptr: *const c_uchar,
) -> i32 {
    let cfg_bytes: Vec<u8> = unsafe { read_data(cfg_ptr, cfg_size) };
    let cfg_str = String::from_utf8(cfg_bytes).unwrap();
    let cfg: Config = serde_json::from_str(cfg_str.as_str()).unwrap();
    let xpub = unsafe { read_xpub(xpub_ptr) };
    let signature = unsafe { read_signature(sig_ptr) };

    let tx_bytes = unsafe { read_data(tx_ptr, tx_sz) };

    let mut deserialiser = cbor_event::de::Deserializer::from(tx_bytes.as_slice());
    let tx: tx::Tx = deserialiser.deserialize_complete().unwrap();

    let txinwitness = tx::TxInWitness::PkWitness(xpub, signature);

    if txinwitness.verify_tx(cfg.protocol_magic, &tx) {
        0
    } else {
        -1
    }
}

mod jrpc {
    use serde::Serialize;
    use serde_json;
    use std::os::raw::c_uchar;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
    struct Error {
        failed: bool,
        loc: String,
        msg: String,
    }
    impl Error {
        fn new(loc: String, msg: String) -> Self {
            Error {
                failed: true,
                loc: loc,
                msg: msg,
            }
        }
    }

    pub fn fail(output_ptr: *mut c_uchar, file: &str, line: u32, msg: String) -> i32 {
        let error = Error::new(format!("{} {}", file, line), msg);

        let output = serde_json::to_string(&error).unwrap();
        let output_bytes = output.into_bytes();

        unsafe { super::write_data(&output_bytes, output_ptr) };
        output_bytes.len() as i32
    }

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
    struct Success<T> {
        failed: bool,
        result: T,
    }
    impl<T: Serialize> Success<T> {
        fn new(result: T) -> Self {
            Success {
                failed: false,
                result: result,
            }
        }
    }

    pub fn ok<T>(output_ptr: *mut c_uchar, result: T) -> i32
    where
        T: Serialize,
    {
        let succ = Success::new(result);

        let output = serde_json::to_string(&succ).unwrap();
        let output_bytes = output.into_bytes();

        unsafe { super::write_data(&output_bytes, output_ptr) };
        output_bytes.len() as i32
    }
}

/// Entry point of jrpc error reporting
macro_rules! jrpc_fail {
    ($output_ptr:ident) => (
        jrpc_fail!($output_ptr, "unknown error")
    );
    ($output_ptr:ident, ) => (
        jrpc_fail!($output_ptr)
    );
    ($output_ptr:ident, $msg:expr) => ({
        jrpc::fail($output_ptr, file!(), line!(), $msg)
    });
    ($output_ptr:ident, $msg:expr, ) => ({
        jrpc_fail!($output_ptr, $msg)
    });
    ($output_ptr:ident, $fmt:expr, $($arg:tt)+) => ({
        jrpc::fail($output_ptr, file!(), line!(), format!($fmt, $($arg)*))
    });
}

macro_rules! jrpc_ok {
    ($output_ptr:ident, $result:expr) => {{
        jrpc::ok($output_ptr, $result)
    }};
    ($output_ptr:ident, $result:expr,) => {{
        jrpc_ok!($output_ptr, $result)
    }};
}

macro_rules! jrpc_try {
    ($output_ptr:ident, $expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => {
                return jrpc_fail!($output_ptr, "{:?}", err);
            }
        }
    };
    ($output_ptr:ident, $expr:expr,) => {
        jrpc_try!($output_ptr, $expr)
    };
}

#[derive(Debug)]
enum Error {
    ErrorUtf8(string::FromUtf8Error),
    ErrorJSON(serde_json::error::Error),
    ErrorCBOR(cbor_event::Error),
    ErrorFEE(fee::Error),
    ErrorBip39(bip39::Error),
    ErrorRindex(rindex::Error),
}
impl convert::From<string::FromUtf8Error> for Error {
    fn from(j: string::FromUtf8Error) -> Self {
        Error::ErrorUtf8(j)
    }
}
impl convert::From<serde_json::error::Error> for Error {
    fn from(j: serde_json::error::Error) -> Self {
        Error::ErrorJSON(j)
    }
}
impl convert::From<cbor_event::Error> for Error {
    fn from(j: cbor_event::Error) -> Self {
        Error::ErrorCBOR(j)
    }
}
impl convert::From<fee::Error> for Error {
    fn from(j: fee::Error) -> Self {
        Error::ErrorFEE(j)
    }
}
impl convert::From<bip39::Error> for Error {
    fn from(j: bip39::Error) -> Self {
        Error::ErrorBip39(j)
    }
}
impl convert::From<rindex::Error> for Error {
    fn from(j: rindex::Error) -> Self {
        Error::ErrorRindex(j)
    }
}

type Result<T> = result::Result<T, Error>;

fn input_string_(input_ptr: *const c_uchar, input_sz: usize) -> Result<String> {
    let input_bytes: Vec<u8> = unsafe { read_data(input_ptr, input_sz) };
    let input = String::from_utf8(input_bytes)?;

    Ok(input)
}

macro_rules! input_json {
    ($output_ptr:ident, $input_ptr:ident, $input_sz:ident) => {{
        let input = jrpc_try!($output_ptr, input_string_($input_ptr, $input_sz));
        jrpc_try!($output_ptr, serde_json::from_str(input.as_str()))
    }};
    ($output_ptr:ident, $input_ptr:ident, $input_sz:ident,) => {{
        input_json!($output_ptr, $input_ptr, $input_sz)
    }};
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Bip44Wallet {
    root_cached_key: hdwallet::XPrv,

    config: Config,
    selection_policy: SelectionPolicy,
    derivation_scheme: hdwallet::DerivationScheme,
}
impl Bip44Wallet {
    fn to_wallet(&self) -> bip44::Wallet {
        let root_key = bip44::RootLevel::from(self.root_cached_key.clone());
        bip44::Wallet::from_cached_key(root_key, self.derivation_scheme)
    }
}

#[no_mangle]
pub extern "C" fn xwallet_create(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let seed = input_json!(output_ptr, input_ptr, input_sz);

    let derivation_scheme = hdwallet::DerivationScheme::V2;
    let selection_policy = SelectionPolicy::FirstMatchFirst;
    let config = Config::default();

    let xprv = hdwallet::XPrv::generate_from_seed(&seed);
    let bip44_wallet = bip44::Wallet::from_root_key(xprv, derivation_scheme);

    let root_key = &**bip44_wallet;

    let wallet = Bip44Wallet {
        root_cached_key: root_key.clone(),
        config: config,
        selection_policy: selection_policy,
        derivation_scheme: derivation_scheme,
    };

    jrpc_ok!(output_ptr, wallet)
}

#[no_mangle]
pub extern "C" fn xwallet_from_master_key(
    input_ptr: *const c_uchar,
    output_ptr: *mut c_uchar,
) -> i32 {
    let xprv = unsafe { read_xprv(input_ptr) };

    let derivation_scheme = hdwallet::DerivationScheme::V2;
    let selection_policy = SelectionPolicy::FirstMatchFirst;
    let config = Config::default();

    let bip44_wallet = bip44::Wallet::from_root_key(xprv, derivation_scheme);

    let root_key = &**bip44_wallet;

    let wallet = Bip44Wallet {
        root_cached_key: root_key.clone(),
        config: config,
        selection_policy: selection_policy,
        derivation_scheme: derivation_scheme,
    };

    jrpc_ok!(output_ptr, wallet)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DaedalusWallet {
    root_cached_key: hdwallet::XPrv,

    config: Config,
    selection_policy: SelectionPolicy,
    derivation_scheme: hdwallet::DerivationScheme,
}
impl DaedalusWallet {
    pub fn to_wallet(&self) -> rindex::Wallet {
        let root_key = rindex::RootKey::new(self.root_cached_key.clone(), self.derivation_scheme);
        rindex::Wallet::from_root_key(self.derivation_scheme, root_key)
    }
}

#[no_mangle]
pub extern "C" fn xwallet_create_daedalus_mnemonic(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let mnemonics_phrase: String = input_json!(output_ptr, input_ptr, input_sz);

    let derivation_scheme = hdwallet::DerivationScheme::V1;
    let selection_policy = SelectionPolicy::FirstMatchFirst;
    let config = Config::default();

    let daedalus_wallet = jrpc_try!(
        output_ptr,
        rindex::Wallet::from_daedalus_mnemonics(
            derivation_scheme,
            &bip39::dictionary::ENGLISH,
            &mnemonics_phrase
        )
    );

    let wallet = DaedalusWallet {
        root_cached_key: (**daedalus_wallet).clone(),
        config: config,
        selection_policy: selection_policy,
        derivation_scheme: derivation_scheme,
    };

    jrpc_ok!(output_ptr, wallet)
}

// TODO: write custom Serialize and Deserialize with String serialisation
#[derive(PartialEq, Eq, Debug)]
pub struct Coin(coin::Coin);
impl serde::Serialize for Coin {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> result::Result<S::Ok, S::Error>
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

    fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Lovelace Ada")
    }

    fn visit_str<'a, E>(self, v: &'a str) -> result::Result<Self::Value, E>
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
    fn deserialize<D>(deserializer: D) -> result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(CoinVisitor())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct TxIn {
    id: tx::TxId,
    index: u32,
}
impl TxIn {
    fn convert(&self) -> tx::TxoPointer {
        tx::TxoPointer {
            id: self.id,
            index: self.index,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Input {
    pub ptr: TxIn,
    pub value: TxOut,
    pub addressing: bip44::Addressing,
}
impl Input {
    fn convert(&self) -> txutils::Input<<bip44::Wallet as Wallet>::Addressing> {
        txutils::Input {
            ptr: self.ptr.convert(),
            value: self.value.convert(),
            addressing: self.addressing.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct WalletSpendInput {
    wallet: Bip44Wallet,
    inputs: Vec<Input>,
    outputs: Vec<TxOut>,
    change_addr: address::ExtendedAddr,
}
impl WalletSpendInput {
    fn get_inputs(&self) -> Vec<txutils::Input<<bip44::Wallet as Wallet>::Addressing>> {
        self.inputs.iter().map(|i| i.convert()).collect()
    }

    fn get_outputs(&self) -> Vec<tx::TxOut> {
        self.outputs.iter().map(|o| o.convert()).collect()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct WalletSpendOutput {
    cbor_encoded_tx: Vec<u8>,
    fee: Coin,
    changed_used: bool,
}

#[no_mangle]
pub extern "C" fn xwallet_spend(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let input: WalletSpendInput = input_json!(output_ptr, input_ptr, input_sz);
    let change = input.change_addr.clone();
    let wallet = input.wallet.to_wallet();
    let config = input.wallet.config;
    let (txaux, fee) = jrpc_try!(
        output_ptr,
        wallet.new_transaction(
            config.protocol_magic,
            input.wallet.selection_policy,
            input.get_inputs().iter(),
            input.get_outputs(),
            &txutils::OutputPolicy::One(input.change_addr)
        )
    );
    let changed_used = txaux.tx.outputs.iter().any(|out| out.address == change);
    let cbor = jrpc_try!(output_ptr, cbor!(&txaux));
    jrpc_ok!(
        output_ptr,
        WalletSpendOutput {
            cbor_encoded_tx: cbor,
            changed_used: changed_used,
            fee: Coin(fee.to_coin())
        }
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxInInfo {
    pub ptr: TxIn,
    pub value: Coin,
    pub addressing: [u32; 2],
}
impl TxInInfo {
    fn convert(&self) -> txutils::TxoPointerInfo<<rindex::Wallet as Wallet>::Addressing> {
        txutils::TxoPointerInfo {
            txin: self.ptr.convert(),
            value: self.value.0,
            address_identified: rindex::Addressing::new(self.addressing[0], self.addressing[1]),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct WalletMoveInput {
    wallet: DaedalusWallet,
    inputs: Vec<TxInInfo>,
    output: address::ExtendedAddr,
}
impl WalletMoveInput {
    fn get_inputs(&self) -> Vec<txutils::TxoPointerInfo<<rindex::Wallet as Wallet>::Addressing>> {
        self.inputs.iter().map(|i| i.convert()).collect()
    }
}

#[no_mangle]
pub extern "C" fn xwallet_move(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let input: WalletMoveInput = input_json!(output_ptr, input_ptr, input_sz);
    let wallet = input.wallet.to_wallet();
    let txaux = jrpc_try!(
        output_ptr,
        wallet.move_transaction(
            input.wallet.config.protocol_magic,
            &input.get_inputs(),
            &txutils::OutputPolicy::One(input.output.clone())
        )
    );
    let cbor = jrpc_try!(output_ptr, cbor!(&txaux.0));
    jrpc_ok!(
        output_ptr,
        WalletSpendOutput {
            cbor_encoded_tx: cbor,
            changed_used: false,
            fee: Coin(txaux.1.to_coin())
        }
    )
}

#[derive(Serialize, Deserialize, Debug)]
struct CreateWalletAccount {
    wallet: Bip44Wallet,
    account: u32,
}
#[derive(Serialize, Deserialize, Debug)]
struct Bip44Account {
    root_cached_key: hdwallet::XPub,
    derivation_scheme: hdwallet::DerivationScheme,
}
impl Bip44Account {
    fn to_account(&self) -> bip44::Account<hdwallet::XPub> {
        let key = bip44::AccountLevel::from(self.root_cached_key.clone());
        bip44::Account::new(key, self.derivation_scheme)
    }
}

#[no_mangle]
pub extern "C" fn xwallet_account(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let input: CreateWalletAccount = input_json!(output_ptr, input_ptr, input_sz);
    let xprv = input
        .wallet
        .to_wallet()
        .account(input.wallet.derivation_scheme, input.account);
    let xpub = (*xprv).public();

    jrpc_ok!(
        output_ptr,
        Bip44Account {
            root_cached_key: xpub,
            derivation_scheme: input.wallet.derivation_scheme
        }
    )
}

#[derive(Serialize, Deserialize, Debug)]
struct GenAddressesInput {
    account: Bip44Account,
    address_type: bip44::AddrType,
    indices: Vec<u32>,
}

#[no_mangle]
pub extern "C" fn xwallet_addresses(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let input: GenAddressesInput = input_json!(output_ptr, input_ptr, input_sz);
    let account = input.account.to_account();
    let changelevel = jrpc_try!(
        output_ptr,
        account.change(input.account.derivation_scheme, input.address_type)
    );

    let mut addresses: Vec<address::ExtendedAddr> = Vec::with_capacity(input.indices.len());
    for index in input.indices.into_iter() {
        let xpub = jrpc_try!(
            output_ptr,
            changelevel.index(input.account.derivation_scheme, index)
        );
        let addr = address::ExtendedAddr::new_simple(*xpub, default_network_magic());
        addresses.push(addr);
    }
    jrpc_ok!(output_ptr, addresses)
}

#[no_mangle]
pub extern "C" fn xwallet_checkaddress(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let input: String = input_json!(output_ptr, input_ptr, input_sz);
    let bytes: Vec<u8> = jrpc_try!(output_ptr, hex::decode(&input));
    let mut deserializer = cbor_event::de::Deserializer::from(bytes.as_slice());
    let _: address::ExtendedAddr = jrpc_try!(output_ptr, deserializer.deserialize_complete());
    jrpc_ok!(output_ptr, true)
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RandomAddressChecker {
    root_key: hdwallet::XPrv,
    payload_key: hdpayload::HDKey,
}

#[no_mangle]
pub extern "C" fn random_address_checker_new(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let input: hdwallet::XPrv = input_json!(output_ptr, input_ptr, input_sz);
    let key = hdpayload::HDKey::new(&input.public());
    let rac = RandomAddressChecker {
        root_key: input,
        payload_key: key,
    };
    jrpc_ok!(output_ptr, rac)
}
#[no_mangle]
pub extern "C" fn random_address_checker_from_mnemonics(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let mnemonics_phrase: String = input_json!(output_ptr, input_ptr, input_sz);

    let wallet = jrpc_try!(
        output_ptr,
        rindex::Wallet::from_daedalus_mnemonics(
            hdwallet::DerivationScheme::V1,
            &bip39::dictionary::ENGLISH,
            &mnemonics_phrase
        )
    );

    let xprv = (**wallet).clone();
    let key = hdpayload::HDKey::new(&xprv.public());
    let rac = RandomAddressChecker {
        root_key: xprv,
        payload_key: key,
    };
    jrpc_ok!(output_ptr, rac)
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RandomAddressCheck {
    checker: RandomAddressChecker,
    addresses: Vec<address::ExtendedAddr>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct FoundRandomAddress {
    address: address::ExtendedAddr,
    addressing: [u32; 2],
}

#[no_mangle]
pub extern "C" fn random_address_check(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let RandomAddressCheck { checker, addresses } = input_json!(output_ptr, input_ptr, input_sz);
    let mut results = Vec::new();
    for addr in addresses {
        if let Some(hdpa) = &addr.attributes.derivation_path.clone() {
            if let Ok(path) = checker.payload_key.decrypt_path(hdpa) {
                results.push(FoundRandomAddress {
                    address: addr,
                    addressing: [path.as_ref()[0], path.as_ref()[1]],
                })
            }
        }
    }
    jrpc_ok!(output_ptr, results)
}

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

#[no_mangle]
pub extern "C" fn encrypt_with_password(
    password_ptr: *const c_uchar,
    password_sz: usize,
    salt_ptr: *const c_uchar,  // expect 32 bytes
    nonce_ptr: *const c_uchar, // expect 12 bytes
    data_ptr: *const c_uchar,
    data_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    use password_encryption_parameter::*;

    let password = unsafe { read_data(password_ptr, password_sz) };
    let salt = unsafe { read_data(salt_ptr, SALT_SIZE) };
    let nonce = unsafe { read_data(nonce_ptr, NONCE_SIZE) };
    let data = unsafe { read_data(data_ptr, data_sz) };

    let key = {
        let mut mac = Hmac::new(Sha512::new(), &password);
        let mut key: Vec<u8> = repeat(0).take(KEY_SIZE).collect();
        pbkdf2(&mut mac, &salt[..], ITER, &mut key);
        key
    };

    let mut tag = [0; TAG_SIZE];
    let mut encrypted: Vec<u8> = repeat(0).take(data.len()).collect();
    {
        ChaCha20Poly1305::new(&key, &nonce, &[]).encrypt(&data, &mut encrypted, &mut tag);
    }

    let mut output = Vec::with_capacity(data.len() + METADATA_SIZE);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&tag);
    output.extend_from_slice(&encrypted);

    unsafe { write_data(&output, output_ptr) };

    output.len() as i32
}

#[no_mangle]
pub extern "C" fn decrypt_with_password(
    password_ptr: *const c_uchar,
    password_sz: usize,
    data_ptr: *const c_uchar,
    data_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    use password_encryption_parameter::*;
    let password = unsafe { read_data(password_ptr, password_sz) };
    let data = unsafe { read_data(data_ptr, data_sz) };

    if data_sz <= METADATA_SIZE {
        // not enough input to decrypt.
        return -2;
    }

    let salt = &data[SALT_START..SALT_END];
    let nonce = &data[NONCE_START..NONCE_END];
    let tag = &data[TAG_START..TAG_END];
    let encrypted = &data[ENCRYPTED_START..];

    let key = {
        let mut mac = Hmac::new(Sha512::new(), &password);
        let mut key: Vec<u8> = repeat(0).take(KEY_SIZE).collect();
        pbkdf2(&mut mac, &salt[..], ITER, &mut key);
        key
    };

    let mut decrypted: Vec<u8> = repeat(0).take(encrypted.len()).collect();
    let decryption_succeed =
        { ChaCha20Poly1305::new(&key, &nonce, &[]).decrypt(&encrypted, &mut decrypted, &tag) };

    if decryption_succeed {
        unsafe { write_data(&decrypted, output_ptr) };
        decrypted.len() as i32
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn redemption_private_to_address(
    private_ptr: *const c_uchar,
    protocol_magic: u32,
    out: *mut c_uchar,
) -> u32 {
    let priv_key = unsafe {
        let slice: &[u8] = std::slice::from_raw_parts(private_ptr, redeem::PRIVATEKEY_SIZE);
        redeem::PrivateKey::from_slice(slice).unwrap()
    };
    let pub_key = priv_key.public();
    let magic = cardano::config::ProtocolMagic::from(protocol_magic);
    let (_, address) = tx::redeem_pubkey_to_txid(&pub_key, magic);
    let address_bytes = cbor!(address).unwrap();
    unsafe { write_data(&address_bytes, out) }
    return address_bytes.len() as u32;
}

#[derive(Serialize, Deserialize, Debug)]
struct WalletRedeemInput {
    protocol_magic: cardano::config::ProtocolMagic,
    redemption_key: [u8; redeem::PRIVATEKEY_SIZE], // hex
    input: TxIn,
    output: TxOut,
}

#[derive(Serialize, Deserialize, Debug)]
struct WalletRedeemOutput {
    cbor_encoded_tx: Vec<u8>,
}

#[no_mangle]
pub extern "C" fn xwallet_redeem(
    input_ptr: *const c_uchar,
    input_sz: usize,
    output_ptr: *mut c_uchar,
) -> i32 {
    let data: WalletRedeemInput = input_json!(output_ptr, input_ptr, input_sz);
    let mut txbuilder = txbuild::TxBuilder::new();
    txbuilder.add_input(&data.input.convert(), data.output.value.0);
    txbuilder.add_output_value(&data.output.convert());
    let tx: tx::Tx = jrpc_try!(
        output_ptr,
        txbuilder.make_tx()
    );
    print!("Tx: {}", tx);
    let redemption_key = jrpc_try!(
        output_ptr,
        redeem::PrivateKey::from_slice(&data.redemption_key)
    );
    print!("Key: {}", redemption_key);
    let witness = jrpc_try!(
        output_ptr,
        create_redemption_witness(data.protocol_magic, &redemption_key, &tx.id())
    );
    let mut finalized = txbuild::TxFinalized::new(tx);
    jrpc_try!(
        output_ptr,
        finalized.add_witness(witness)
    );
    let txaux: tx::TxAux = jrpc_try!(
        output_ptr,
        finalized.make_txaux()
    );
    let cbor = jrpc_try!(output_ptr, cbor!(&txaux));
    jrpc_ok!(output_ptr, WalletRedeemOutput {
        cbor_encoded_tx: cbor
    })
}

fn create_redemption_witness(
    protocol_magic: cardano::config::ProtocolMagic,
    key: &redeem::PrivateKey,
    txid: &tx::TxId,
) -> redeem::Result<tx::TxInWitness> {
    // TODO: actual implementation
    let s32 = (0..64).map(|_| "f").collect::<String>();
    let s64 = (0..128).map(|_| "f").collect::<String>();
    let pk = redeem::PublicKey::from_hex(&s32);
    let sg = redeem::Signature::from_hex(&s64);
    return pk.and_then(|k| sg.map(|s| (k, s)))
        .map(|(k,s)| tx::TxInWitness::RedeemWitness(k, s));
}