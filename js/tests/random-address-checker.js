const expect = require('chai').expect;
const CardanoCrypto = require('../../dist/index.js');

const NUM_UNKNOWN_ADDRESSES        = 10000;
const NUM_PAYLOAD_REPLAY_ADDRESSES = 10000;
const NUM_KNOWN_ADDRESSES          = 10000;
const XPRV = "301604045de9138b8b23b6730495f7e34b5151d29bA3456BC9B332F6F084A551D646BC30CF126FA8ED776C05A8932A5AB35C8BAC41EB01BB9A16CFE229B94B405D3661DEB9064F2D0E03FE85D68070B2FE33B4916059658E28AC7F7F91CA4B12";
const UNKNOWN_ADDRESS        = "DdzFFzCqrht8bHGhehfWkQHYQ6oXwXanJF12e2AmqwerXV5WE4NY95VmGTcZH676VQpjjPWczLq68f1CmbdkEKkQ8JDEVDYqmtpyq2s1";
const PAYLOAD_REPLAY_ADDRESS = "3s4ud2BC9ZiQN2tNZiXY15JGmHHLDXjP4fmTSWBL1bHCKqegYqNQxLzz4SdVZSAkkGBhASbcgSK2SFqb9wPFjPsYt92qbJQWiaXiDUK";
const KNOWN_ADDRESS          = "3s4ud2BC9ZiPJusHpTiB8eRU3azPVvGRV4ho2Z2mvaW7bMtKSZ5CwqKqHgS1AGqyXkvnE1SWZ6Yah6LZ1AZVdiqXnqKS9YDJfjtkPvw";

describe('Random Address Checker', async function() {
    let checker;

    before(async () => {
        await CardanoCrypto.loadRustModule()
        checker = CardanoCrypto.RandomAddressChecker.newChecker(XPRV).result;
    });

    it("Check " + NUM_UNKNOWN_ADDRESSES + " random addresses are not mine", function() {
        const addresses = Array.apply(null, Array(NUM_UNKNOWN_ADDRESSES)).map(() => { return UNKNOWN_ADDRESS; });
        let result = CardanoCrypto.RandomAddressChecker.checkAddresses(checker, addresses);

        expect(result.failed).equals(false);
        expect(result.result.length).equals(0);
    });
    it("Check " + NUM_PAYLOAD_REPLAY_ADDRESSES + " random addresses are not mines (payload replay)", function() {
        const addresses = Array.apply(null, Array(NUM_KNOWN_ADDRESSES)).map(() => { return PAYLOAD_REPLAY_ADDRESS; });
        let result = CardanoCrypto.RandomAddressChecker.checkAddresses(checker, addresses);

        expect(result.failed).equals(false);
        expect(result.result.length).equals(0);
    });

    it("Check " + NUM_KNOWN_ADDRESSES + " random addresses are mines", function() {
        const addresses = Array.apply(null, Array(NUM_KNOWN_ADDRESSES)).map(() => { return KNOWN_ADDRESS; });
        let result = CardanoCrypto.RandomAddressChecker.checkAddresses(checker, addresses);

        expect(result.failed).equals(false);
        expect(result.result.length).equals(NUM_KNOWN_ADDRESSES);
    });
});

