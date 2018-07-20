const expect = require('chai').expect;
const CardanoCrypto = require('../../dist/index.js');

const INITIAL_ENTROPY = new Uint8Array([0,0,0,0    ,0,0,0,0    ,0,0,0,0,   0,0,0,0]);
const PASSWORD = "CARDANO";
const EXPECTED_ADDRESSES =
    [ 'Ae2tdPwUPEZ8WSB8MZtWJzMDj4kVAzEWtMAr8XT1Wysef4kUU5XpLNyER6o'
    , 'Ae2tdPwUPEZMA3qZLkEpGex7c1AQUHa9jCjR9dirbEQZXiwCfRbCFJkhMhw'
    , 'Ae2tdPwUPEZ6ZXFzm5MLqz4ESF6zFsw7hAExwXncAMwz4nFAuL1pPUrUNFW'
    ];

describe('Enhanced Entropy', async function() {
    let xprv = null;
    let wallet = null;
    let account = null;

    before(async () => {
        await CardanoCrypto.loadRustModule()
    });

    it("generate msater key", function() {
        xprv          = CardanoCrypto.HdWallet.fromEnhancedEntropy(INITIAL_ENTROPY, PASSWORD);
        expect(xprv).not.equals(null);
    });
    it("create an wallet", function() {
        const result  = CardanoCrypto.Wallet.fromMasterKey(xprv);
        expect(result.failed).equals(false);
        wallet = result.result;
    });
    it("create an account", function() {
        const result  = CardanoCrypto.Wallet.newAccount(wallet, 0);
        expect(result.failed).equals(false);
        account = result.result;
    });
    it("generate addresses", function() {
        const result = CardanoCrypto.Wallet.generateAddresses(account, "External", [0,1,5]);
        expect(result.failed).equals(false);
        const addresses = result.result;
        expect(addresses.length).equals(EXPECTED_ADDRESSES.length);
        for (let index = 0; index < addresses.length; index++) {
            const expected = EXPECTED_ADDRESSES[index];
            const address  = addresses[index];

            expect(address).equals(expected);
        }
    });
});
