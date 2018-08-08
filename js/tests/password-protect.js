const expect = require('chai').expect;
const CardanoCrypto = require('../../dist/index.js');

const NONCE = new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11]);
const SALT = new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31]);
const       PASSWORD = new Uint8Array([0,1,2,3,4,5,6,7,8,9,10]);
const WRONG_PASSWORD = new Uint8Array([10,9,8,7,6,5,4,3,2,1,0]);
const DATA = new Uint8Array([42,10,93,102,192,0,1,172,223]);
const ENCRYPTED = new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,0,1,2,3,4,5,6,7,8,9,10,11,145,155,212,135,181,55,89,114,98,97,155,82,90,130,252,21,212,239,182,84,208,111,3,59,122 ]);

describe('Password Protect', async function() {
    before(async () => {
        await CardanoCrypto.loadRustModule()
    });

    it("encrypt", function() {
        const result = CardanoCrypto.PasswordProtect.encryptWithPassword(PASSWORD, SALT, NONCE, DATA);
        expect(result).deep.equals(ENCRYPTED);
    });
    it("decrypt", function() {
        const result = CardanoCrypto.PasswordProtect.decryptWithPassword(PASSWORD, ENCRYPTED);
        expect(result).deep.equals(DATA);
    });
    it("decrypt wrong password", function() {
        const result = CardanoCrypto.PasswordProtect.decryptWithPassword(WRONG_PASSWORD, ENCRYPTED);
        expect(result).deep.equals(false);
    });
});
