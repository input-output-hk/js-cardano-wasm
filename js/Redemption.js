import iconv from 'iconv-lite';
import RustModule from './RustModule';
import { newArray, newArray0, copyArray } from './utils/arrays';
import { apply } from './utils/functions';

export const REDEMPTION_PRIVATE_KEY_SIZE = 32;
const MAX_OUTPUT_SIZE = 4096;

/**
 * @param module        - the WASM module that is used for crypto operations
 * @param redemptionKey - the private redemption key, needs to be {@link REDEMPTION_PRIVATE_KEY_SIZE}
 * @param magic         - protocol magic integer
 * @returns {*}         - returns false if the seed is not of the valid length, or returns the redemption address
 */
export const redemptionKeyToAddress = (module, redemptionKey, magic) => {
    if (redemptionKey.length !== REDEMPTION_PRIVATE_KEY_SIZE) {
        return false;
    }
    const bufkey = newArray(module, seed);
    const bufaddr = newArray0(module, 1024);
    const rs = module.redemption_private_to_address(bufkey, magic, bufaddr);
    let result = copyArray(module, bufaddr, rs);
    module.dealloc(bufkey);
    module.dealloc(bufaddr);
    return result;
};

/**
 * @param module        - the WASM module that is used for crypto operations
 * @param redemptionKey - the private redemption key, needs to be {@link REDEMPTION_PRIVATE_KEY_SIZE}
 * @param input         - single input as: { id, index }
 * @param output        - single output as: { address, value }
 * @param magic         - protocol magic integer
 * @returns {*}         - returns false if the seed is not of the valid length, or returns the response as: { cbor_encoded_tx }
 */
export const createRedemptionTransaction = (module, redemptionKey, input, output, magic) => {
    if (redemptionKey.length !== REDEMPTION_PRIVATE_KEY_SIZE) {
        return false;
    }
    const input_obj = { protocol_magic: magic, redemption_key: redemptionKey, input, output };
    const input_str = JSON.stringify(input_obj);
    const input_array = iconv.encode(input_str, 'utf8');

    const bufinput  = newArray(module, input_array);
    const bufoutput = newArray0(module, MAX_OUTPUT_SIZE);

    let rsz = module.xwallet_redeem(bufinput, input_array.length, bufoutput);
    let output_array = copyArray(module, bufoutput, rsz);

    module.dealloc(bufoutput);
    module.dealloc(bufinput);

    let output_str = iconv.decode(Buffer.from(output_array), 'utf8');
    return JSON.parse(output_str);
};

export default {
    redemptionKeyToAddress: apply(redemptionKeyToAddress, RustModule),
    createRedemptionTransaction: apply(createRedemptionTransaction, RustModule),
};
