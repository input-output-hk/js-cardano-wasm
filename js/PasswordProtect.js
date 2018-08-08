import RustModule from './RustModule';
import { newArray, newArray0, copyArray } from './utils/arrays';
import { apply } from './utils/functions';

/**
 * encrypt the given data with the password, salt and nonce.
 *
 * It is users responsibility to provide the nonce and the salt.
 *
 * @param module - the WASM module that is used for crypto operations
 * @param password  - if it was a human readable password, prefer UTF8 encoded string into bytes.
 * @param data      - bytes to password protect
 * @param salt      - 32 random bytes
 * @param nonce     - 12 random bytes
 * @returns {*}     - password protected data or null of the encryption failed. Function returns false if salt or nonce are of invalid size
 */
export const encryptWithPassword = (module, password, salt, nonce, data) => {
    const SALT_SIZE  = 32;
    const NONCE_SIZE = 12;
    const TAG_SIZE   = 16;

    if (salt.length !== SALT_SIZE) { return false; }
    if (nonce.length !== NONCE_SIZE) { return false; }

    const result_size = data.length + TAG_SIZE + NONCE_SIZE + SALT_SIZE;

    const bufpassword = newArray(module, password);
    const bufdata     = newArray(module, data);
    const bufsalt     = newArray(module, salt);
    const bufnonce    = newArray(module, nonce);
    const bufoutput   = newArray0(module, result_size);

    const result = module.encrypt_with_password(
        bufpassword, password.length,
        bufsalt,
        bufnonce,
        bufdata, data.length,
        bufoutput
    );

    let output_array = null;
    if (result === result_size) {
        output_array = copyArray(module, bufoutput, result);
    }

    module.dealloc(bufoutput);
    module.dealloc(bufsalt);
    module.dealloc(bufnonce);
    module.dealloc(bufdata);
    module.dealloc(bufpassword);

    return output_array;
};

/**
 * decrypt the given data with the password.
 *
 * @param module - the WASM module that is used for crypto operations
 * @param password  - if it was a human readable password, prefer UTF8 encoded string into bytes.
 * @param data      - encrypted data
 * @returns {*}     - decrypted data or null if an error occurred or false of it is wrong password
 */
export const decryptWithPassword = (module, password, data) => {
    const SALT_SIZE  = 32;
    const NONCE_SIZE = 12;
    const TAG_SIZE   = 16;

    const result_size = data.length - TAG_SIZE - NONCE_SIZE - SALT_SIZE;

    const bufpassword = newArray(module, password);
    const bufdata     = newArray(module, data);
    const bufoutput   = newArray0(module, result_size);

    const result = module.decrypt_with_password(
        bufpassword, password.length,
        bufdata, data.length,
        bufoutput
    );

    let output_array = null;
    if (result === -1) {
        output_array = false;
    } else if (result === result_size) {
        output_array = copyArray(module, bufoutput, result);
    }

    module.dealloc(bufoutput);
    module.dealloc(bufdata);
    module.dealloc(bufpassword);

    return output_array;
};


export default {
  encryptWithPassword: apply(encryptWithPassword, RustModule),
  decryptWithPassword: apply(decryptWithPassword, RustModule)
};
