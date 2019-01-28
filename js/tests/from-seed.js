const expect = require('chai').expect;
const CardanoCrypto = require('../../dist/index.js');

const SEED = Array(32).fill(0);

describe('Wallet FromSeed', async function () {
    let xprv = null;
    let wallet = null;
    let account = null;

    before(async () => {
        await CardanoCrypto.loadRustModule()
    });

    it("check seed size", function () {
        expect(SEED.length).equals(CardanoCrypto.HdWallet.SEED_SIZE);
    });
    it("create a wallet", function () {
        const result = CardanoCrypto.Wallet.fromSeed(SEED);
        expect(result.failed).equals(false);
        wallet = result.result;
    });
});
