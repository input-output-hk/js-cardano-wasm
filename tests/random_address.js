const expect = require('chai').expect;
const Cardano = require('../js/wallet.js');

const ITERATION_LENGTH = 10000;

describe('Wallet\'s addresses with random indexes', function() {
    let root_xprv = Cardano.XPrv.from_seed(Array.apply(null, {length: 32}));
    let root_xpub = root_xprv.public();

    let xpub = root_xprv.derive(0x80000001).derive(0x80000002).public();

    let unknown_address = Cardano.Address.from_base58("DdzFFzCqrhtCUjHyzgvgigwA5soBgDxpc8WfnG1RGhrsRrWMV8uKdpgVfCXGgNuXhdN4qxPMvRUtbUnWhPzxSdxJrWzPqACZeh6scCH5");

    let checker = Cardano.RandomAddressChecker.new(root_xprv);

    it('check one random address is not mine', function() {
        expect(checker.check_address(unknown_address)).equals(false);
    });
    let addresses = Cardano.Addresses.new();
    for (let index = 0; index < ITERATION_LENGTH; index++) {
        addresses.push("DdzFFzCqrhtCUjHyzgvgigwA5soBgDxpc8WfnG1RGhrsRrWMV8uKdpgVfCXGgNuXhdN4qxPMvRUtbUnWhPzxSdxJrWzPqACZeh6scCH5");
    }
    it('check ' + ITERATION_LENGTH + ' random addresses aren\'t mine', function() {
        let filtered_addresses = checker.check_addresses(addresses);
        expect(filtered_addresses.is_empty()).equals(true);
    });
});

describe('Wallet\'s addresses with random indexes', function() {
    let root_xprv = Cardano.XPrv.from_seed(Array.apply(null, {length: 32}));
    let root_xpub = root_xprv.public();

    let xpub = root_xprv.derive(0x80000001).derive(0x80000002).public();

    let payload = Cardano.Payload.new(root_xpub, [0x80000001, 0x80000002]);

    let known_address = xpub.to_adddress_with_payload(payload);

    let checker = Cardano.RandomAddressChecker.new(root_xprv);
    it('check one random address is mine', function() {
        expect(checker.check_address(known_address)).equals(true);
    });
    let addresses = Cardano.Addresses.new();
    for (let index = 0; index < ITERATION_LENGTH; index++) {
        addresses.push(known_address.to_base58());
    }
    it('check ' + ITERATION_LENGTH + ' addresses are all mine', function() {
        let filtered_addresses = checker.check_addresses(addresses);
        expect(filtered_addresses.is_empty()).equals(false);
        expect(filtered_addresses.len()).equals(ITERATION_LENGTH);
    });
});
