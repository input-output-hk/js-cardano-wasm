const expect = require('chai').expect;
const Cardano = require('../js/wallet.js');

const TEST =
  { pubkey: [28, 12, 58, 225, 130, 94, 144, 182, 221, 218, 63, 64, 161, 34, 192, 7, 225, 0, 142, 131, 178, 225, 2, 193, 66, 186, 239, 183, 33, 215, 44, 26, 93, 54, 97, 222, 185, 6, 79, 45, 14, 3, 254, 133, 214, 128, 112, 178, 254, 51, 180, 145, 96, 89, 101, 142, 40, 172, 127, 127, 145, 202, 75, 18]
  , payload: [229, 123, 216, 139, 186, 31, 136, 170, 141, 206, 193, 201, 206, 53, 33, 116, 160, 227, 158, 62]
  , address: [130,216,24,88,56,131,88,28,162,248,66,62,170,11,93,77,216,98,8,209,204,187,31,223,121,177,156,148,244,180,194,111,27,69,192,6,161,1,85,84,229,123,216,139,186,31,136,170,141,206,193,201,206,53,33,116,160,227,158,62,0,26,101,245,21,213]
  };

describe('Public Key and Addresses', function() {
    let xpub = Cardano.XPub.from_slice(TEST.pubkey);
    let address = Cardano.Address.from_slice(TEST.address);
    let payload = Cardano.Payload.from_slice(TEST.payload);

    it('Address has a payload', function() {
        expect(address.has_payload()).equals(true);
    });

    let address_bis = xpub.to_adddress_with_payload(payload).to_base58();
    let address_ref = address.to_base58();

    it('Recreate address from the payload and publickey', function() {
        expect(address_bis).equals(address_ref);
    });
});
