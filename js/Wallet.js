import iconv from 'iconv-lite';
import RustModule from './RustModule';
import { newArray, newArray0, copyArray } from './utils/arrays';
import { apply } from './utils/functions';
import { base16 } from './utils/strings';

const MAX_OUTPUT_SIZE = 4096;

/**
 * Create a wallet object from the given seed.
 *
 * @param module - the WASM module that is used for crypto operations
 * @param seed   - the 32 bytes seed to generate the wallet from
 * @returns {*}  - a wallet object (JSON object)
 */
export const fromSeed = (module, seed) => {
    const input_str = JSON.stringify(seed);
    const input_array = iconv.encode(input_str, 'utf8');

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, MAX_OUTPUT_SIZE);

    let rsz = module.xwallet_create(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};

/**
 * Create a wallet object from the given seed.
 *
 * @param module - the WASM module that is used for crypto operations
 * @param mnemonics - the 12 words mnemonic phrase (as one string)
 * @returns {*}  - a wallet object (JSON object)
 */
export const fromDaedalusMnemonic = (module, mnemonics) => {
    const input_str = JSON.stringify(mnemonics);
    const input_array = iconv.encode(input_str, 'utf8');

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, MAX_OUTPUT_SIZE);

    let rsz = module.xwallet_create_daedalus_mnemonic(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};


/**
 * Create an account, for public key derivation (using bip44 model).
 *
 * @example
 * ```
 * const wallet  = CardanoCrypto.Wallet.fromSeed([0,1,2,3,4..]).result;
 * const account = CardanoCrypto.Wallet.account(wallet, 0).result;
 * ```
 *
 * @param module - the WASM module that is used for crypto operations
 * @param wallet  - the wallet as created by `Wallet.fromSeed`.
 * @param account - the account number (0 to (0x80000000 - 1)).
 * @returns {*}  - a list of ready to use addresses
 */
export const newAccount = (module, wallet, account, type, indices) => {
    const input = { wallet: wallet
                  , account: account
                  };
    const input_str = JSON.stringify(input);
    const input_array = iconv.encode(input_str, 'utf8');

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, MAX_OUTPUT_SIZE);

    let rsz = module.xwallet_account(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};

/**
 * Generate addresses for the given wallet.
 *
 * @example
 * ```
 * const wallet    = CardanoCrypto.Wallet.fromSeed([0,1,2,3,4..]).result;
 * const account   = CardanoCrypto.Wallet.newAccount(wallet, 0).result;
 * const addresses = CardanoCrypto.Wallet.generateAddresses(account, "External", [0,1,2,3,4]).result;
 * ```
 *
 * @param module - the WASM module that is used for crypto operations
 * @param account - the account as create by `CardanoCrypto.Wallet.newAccount`
 * @param type    - the addresses type ("Internal" or "External")
 * @param indices - the addresse indices
 * @returns {*}  - a list of ready to use addresses
 */
export const generateAddresses = (module, account, type, indices) => {
    const input = { account, account
                  , address_type: type
                  , indices: indices
                  };
    const input_str = JSON.stringify(input);
    const input_array = iconv.encode(input_str, 'utf8');

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, MAX_OUTPUT_SIZE);

    let rsz = module.xwallet_addresses(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};

/**
 * Generate a ready to send, signed, transaction.
 *
 * @example
 * ```
 * let seed = 'compute seed from mnemonic';
 * let wallet = CardanoCrypto.Wallet.fromSeed(seed).result;
 *
 * // the inputs are the resolved UTxO
 * //
 * // they contained the TxId and the index of where the TxOut is and the content of the
 * // TxOut.
 * let inputs =
 *     [ { ptr: { index: 42
 *              , id: "1c7b178c1655628ca87c7da6a5d9d13c1e0a304094ac88770768d565e3d20e0b"
 *              }
 *       , value: { address: "DdzFFzCqrhtCUjHyzgvgigwA5soBgDxpc8WfnG1RGhrsRrWMV8uKdpgVfCXGgNuXhdN4qxPMvRUtbUnWhPzxSdxJrWzPqACZeh6scCH5"
 *                , value: "92837348"
 *                }
 *       , addressing: { account: 0, change: 0, index: 9 }
 *       }
 *     ];
 *
 * // where we want to send money to
 * let outputs =
 *     [ { address: "DdzFFzCqrhtCUjHyzgvgigwA5soBgDxpc8WfnG1RGhrsRrWMV8uKdpgVfCXGgNuXhdN4qxPMvRUtbUnWhPzxSdxJrWzPqACZeh6scCH5"
 *       , value: "666"
 *       }
 *     ];
 *
 * // where the change will need to be sent
 * let change_addr = "DdzFFzCqrhtCUjHyzgvgigwA5soBgDxpc8WfnG1RGhrsRrWMV8uKdpgVfCXGgNuXhdN4qxPMvRUtbUnWhPzxSdxJrWzPqACZeh6scCH5";
 *
 * let result = CardanoCrypto.Wallet.spend(wallet, inputs, outputs, change_addr).result;
 *
 * console.log("fees of the transaction: ", result.fee);
 * console.log("bytes array (encoded tx): ", result.cbor_encoded_tx);
 * console.log("change has been used? ", result.change_used);
 * ```
 *
 * @param module - the WASM module that is used for crypto operations
 * @param wallet - The wallet object as created by the `fromSeed` function
 * @param inputs - the list of inputs
 * @param outputs - the list of payment to make
 * @param change_addr - the address to send the change to
 * @returns {*}  - a ready to use, signed transaction encoded in cbor, the fee computed and the JSON encoded version of the TxAux.
 */
export const spend = (module, wallet, inputs, outputs, change_addr) => {
    const input = { wallet: wallet
                  , inputs: inputs
                  , outputs: outputs
                  , change_addr: change_addr
                  };
    const input_str = JSON.stringify(input);
    const input_array = iconv.encode(input_str, 'utf8');

    const OUTPUT_SIZE = (inputs.length + outputs.length + 1) * 4096;

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, OUTPUT_SIZE);

    let rsz = module.xwallet_spend(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};

/**
 * Move all UTxO to a single address
 *
 * @example
 * ```
 * let daedalusMnemonics = "hair hint inside this bicycle trip protect they person tired mouse tribe";
 * let wallet = CardanoCrypto.Wallet.fromDaedalusMnemonic(daedalusMnemonics).result;
 *
 * // the inputs are the resolved UTxO
 * //
 * // they contained the TxId and the index of where the TxOut is and the content of the
 * // TxOut.
 * let inputs =
 *     [ { txin: { index: 42
 *               , id: "1c7b178c1655628ca87c7da6a5d9d13c1e0a304094ac88770768d565e3d20e0b"
 *               }
 *       , value: "92837348"
 *       , addressing: [0x80000000, 0x80000000]
 *       }
 *     ];
 *
 * // where the output is sent will need to be sent
 * let output = "Ae2tdPwUPEZDLCa35PPESynyrrBefJ9FMDjgju3Rri6WrDigFjniBW5muic";
 *
 * let result = CardanoCrypto.Wallet.move(wallet, inputs, output).result;
 *
 * console.log("fees of the transaction: ", result.fee);
 * console.log("bytes array (encoded tx): ", result.cbor_encoded_tx);
 * ```
 *
 * @param module - the WASM module that is used for crypto operations
 * @param wallet - The wallet object as created by the `fromSeed` function
 * @param inputs - the list of inputs
 * @param output - the address to send all the funds
 * @returns {*}  - a ready to use, signed transaction encoded in cbor, the fee computed and the JSON encoded version of the TxAux.
 */
export const move = (module, wallet, inputs, output) => {
    const input = { wallet: wallet
                  , inputs: inputs
                  , output: output
                  };
    const input_str = JSON.stringify(input);
    const input_array = iconv.encode(input_str, 'utf8');

    const OUTPUT_SIZE = (inputs.length + 1) * 4096;

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, OUTPUT_SIZE);

    let rsz = module.xwallet_move(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};


/**
 * Check if the given hexadecimal string is a valid Cardano Extended Address
 *
 * @param module  - the WASM module that is used for crypto operations
 * @param address - the hexadecimal address to check
 * @returns {*}  - true or false
 */
export const checkAddress = (module, address) => {
    const input_str = JSON.stringify(address);
    const input_array = iconv.encode(input_str, 'utf8');

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, MAX_OUTPUT_SIZE);

    let rsz = module.xwallet_checkaddress(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};

export default {
  fromSeed: apply(fromSeed, RustModule),
  fromDaedalusMnemonic: apply(fromDaedalusMnemonic, RustModule),
  newAccount: apply(newAccount, RustModule),
  generateAddresses: apply(generateAddresses, RustModule),
  spend: apply(spend, RustModule),
  move: apply(move, RustModule),
  checkAddress: apply(checkAddress, RustModule),
};
