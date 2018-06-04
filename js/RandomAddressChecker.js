import iconv from 'iconv-lite';
import RustModule from './RustModule';
import { newArray, newArray0, copyArray } from './utils/arrays';
import { apply } from './utils/functions';

const MAX_OUTPUT_SIZE = 4096000;

/**
 * Create a random address checker, this will allow validating
 * addresses:
 *
 * - can we decrypt the address payload?
 * - can we reconstruct the address from the decrypted payload?
 *
 * @param module - the WASM module that is used for crypto operations
 * @param xprv   - the root private key
 * @returns {*}  - a random address checker (JSON object)
 */
export const newChecker = (module, xprv) => {
    const input_str = JSON.stringify(xprv);
    const input_array = iconv.encode(input_str, 'utf8');

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, MAX_OUTPUT_SIZE);

    let rsz = module.random_address_checker_new(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};

/**
 * Check if the given addresses are valid:
 *
 * - can we decrypt the address payload?
 * - can we reconstruct the address from the decrypted payload?
 *
 * @param module    - the WASM module that is used for crypto operations
 * @param checker   - the random address checker
 * @param addresses - an array of addresses (base58 encoded)
 * @returns {*}     - an array of addresses that are associated to the given checker.
 */
export const checkAddresses = (module, checker, addresses) => {
    const input_str = JSON.stringify({checker: checker, addresses: addresses});
    const input_array = iconv.encode(input_str, 'utf8');

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, MAX_OUTPUT_SIZE);

    let rsz = module.random_address_check(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};

export default {
  newChecker: apply(newChecker, RustModule),
  checkAddresses: apply(checkAddresses, RustModule)
};

