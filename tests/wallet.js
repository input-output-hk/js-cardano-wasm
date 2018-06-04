const expect = require('chai').expect;
const Cardano = require('../js/wallet.js');

describe('Wallet properties', function() {
    let xprv_0 = Cardano.XPrv.from_seed(Array.apply(null, {length: 32}));
    let xprv_1 = xprv_0.derive_v2(42);
    let xpub_0 = xprv_0.public();
    let xpub_1 = xpub_0.derive_v2(42);
    let xpub_1_ = xprv_1.public();
    let message = [0,1,2,3,4,5];

    let signature = xprv_0.sign(message);

    it('Paired PubKey verifies signature', function() {
        expect(xpub_0.verify(signature, message)).equals(true);
    });
    it('Not Paired PubKey failes to verify signature', function() {
        expect(xpub_1.verify(signature, message)).equals(false);
    });
    it('Soft derivation', function() {
        expect(xpub_1.to_hex()).equals(xpub_1_.to_hex());
    });
});

