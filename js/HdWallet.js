import iconv from 'iconv-lite';
import RustModule from './RustModule';
import { newArray, newArray0, copyArray } from './utils/arrays';
import { apply } from './utils/functions';

/**
 * generate an eXtended private key from the given entropy and the given password.
 *
 * The password is a string, it will be encoded in utf8 before being passed
 * to the lower function.
 *
 * @param module    - the WASM module that is used for crypto operations
 * @param entropy   - 16, 20, 24, 28 or 32 bytes of entropy (see BIP39 entropy)
 * @param password  - password string
 * @returns {*}     - an eXtended private key (or null) if the given entropy is of invalid size.
 */
export const fromEnhancedEntropy = (module, entropy, password) => {
  const passwordArray = iconv.encode(password, 'utf8');

  const bufentropy = newArray(module, entropy);
  const bufpassword = newArray(module, passwordArray);
  const bufxprv = newArray0(module, 96);
  let result = module.wallet_from_enhanced_entropy(bufentropy, entropy.length, bufpassword, passwordArray.length, bufxprv);
  let xprv = null;
  if (result === 0) {
    xprv = copyArray(module, bufxprv, 96);
  }
  module.dealloc(bufpassword);
  module.dealloc(bufentropy);
  module.dealloc(bufxprv);
  return xprv;
};


export const fromSeed = (module, seed) => {
  const bufseed = newArray(module, seed);
  const bufxprv = newArray0(module, 96);
  module.wallet_from_seed(bufseed, bufxprv);
  let result = copyArray(module, bufxprv, 96);
  module.dealloc(bufseed);
  module.dealloc(bufxprv);
  return result;
};

export const fromDaedalusSeed = (module, seed) => {
  const bufseed = newArray(module, seed);
  const bufxprv = newArray0(module, 96);
  module.wallet_from_daedalus_seed(bufseed, bufxprv);
  let result = copyArray(module, bufxprv, 96);
  module.dealloc(bufseed);
  module.dealloc(bufxprv);
  return result;
};

export const toPublic = (module, xprv) => {
  const bufxprv = newArray(module, xprv);
  const bufxpub = newArray0(module, 64);
  module.wallet_to_public(bufxprv, bufxpub);
  let result = copyArray(module, bufxpub, 64);
  module.dealloc(bufxprv);
  module.dealloc(bufxpub);
  return result;
};

export const derivePrivate = (module, xprv, index) => {
  const bufxprv = newArray(module, xprv);
  const bufchild = newArray0(module, xprv.length);
  module.wallet_derive_private(bufxprv, index, bufchild);
  let result = copyArray(module, bufchild, xprv.length);
  module.dealloc(bufxprv);
  module.dealloc(bufchild);
  return result;
};

export const derivePublic = (module, xpub, index) => {
  if (index >= 0x80000000) {
    throw new Error('cannot do public derivation with hard index');
  }
  const bufxpub = newArray(module, xpub);
  const bufchild = newArray0(module, xpub.length);
  const r = module.wallet_derive_public(bufxpub, index, bufchild);
  const result = copyArray(module, bufchild, xpub.length);
  module.dealloc(bufxpub);
  module.dealloc(bufchild);
  return result
};

export const sign = (module, xprv, msg) => {
  let length = msg.length;
  const bufsig = newArray0(module, 64);
  const bufxprv = newArray(module, xprv);
  const bufmsg = newArray(module, msg);
  module.wallet_sign(bufxprv, bufmsg, length, bufsig);
  let result = copyArray(module, bufsig, 64);
  module.dealloc(bufxprv);
  module.dealloc(bufmsg);
  module.dealloc(bufsig);
  return result
};

export const publicKeyToAddress = (module, xpub, payload) => {
  const bufxpub    = newArray(module, xpub);
  const bufpayload = newArray(module, payload);
  const bufaddr    = newArray0(module, 1024);

  let rs = module.wallet_public_to_address(bufxpub, bufpayload, payload.length, bufaddr);
  let addr = copyArray(module, bufaddr, rs);

  module.dealloc(bufaddr);
  module.dealloc(bufpayload);
  module.dealloc(bufxpub);

  return addr;
};

export const addressGetPayload = (module, address) => {
  const bufaddr    = newArray(module, address);
  const bufpayload = newArray0(module, 1024);

  let rs = module.wallet_address_get_payload(bufaddr, address.length, bufpayload);
  let payload = null;
  if (rs > 0) {
      payload = copyArray(module, bufpayload, rs);
  }

  module.dealloc(bufpayload);
  module.dealloc(bufaddr);

  return payload;
};


export default {
  fromSeed: apply(fromSeed, RustModule),
  fromEnhancedEntropy: apply(fromEnhancedEntropy, RustModule),
  fromDaedalusSeed: apply(fromDaedalusSeed, RustModule),
  toPublic: apply(toPublic, RustModule),
  derivePrivate: apply(derivePrivate, RustModule),
  derivePublic: apply(derivePublic, RustModule),
  sign: apply(sign, RustModule),
  publicKeyToAddress: apply(publicKeyToAddress, RustModule),
  addressGetPayload: apply(addressGetPayload, RustModule)
};
