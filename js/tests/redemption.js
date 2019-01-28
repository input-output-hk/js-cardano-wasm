const expect = require('chai').expect;
const CardanoCrypto = require('../../dist/index.js');
const bs58 = require('bs58');
const cbor = require('cbor');
const crc = require('crc');

const TEST_VECTORS = [
  {
    redemptionKey: Buffer.from('qXQWDxI3JrlFRtC4SeQjeGzLbVXWBomYPbNO1Vfm1T4=', 'base64'),
    expectedAddress: 'Ae2tdPwUPEZ1xZTLczMGYL5PhADi1nbFmESqS9vUuLkyUe1isQ77TRUE9NS',
    expectedPublicKey: 'faf8ed5be127c8ea22e3a0f1b9335f910aaa672e96c41d7cbdcaed897a450667',
    expectedSignature: '80ed81b9f3683684fdb7c286eb7cfa63580a239ed6bf67f71643d290de2206855171003c7f33cad04e9fa28ee5d5c18c4e5f0d788ae2a63fa492ba7b59995c03',
    txId: new Uint8Array([0xaa,0xd7,0x8a,0x13,0xb5,0x0a,0x01,0x4a,0x24,0x63,0x3c,0x7d,0x44,0xfd,0x8f,0x8d,0x18,0xf6,0x7b,0xbb,0x3f,0xa9,0xcb,0xce,0xdf,0x83,0x4a,0xc8,0x99,0x75,0x9d,0xcd]),
    txOutIndex: 1,
    coinValue: 12345678
  }
];

let mkTest = (i) => {
    const { redemptionKey, expectedAddress, expectedPublicKey, expectedSignature, txId, txOutIndex, coinValue } = TEST_VECTORS[i];
    const cfg = CardanoCrypto.Config.defaultConfig();

    describe('Test ' + i, function() {
        before(async () => {
            await CardanoCrypto.loadRustModule()
        });

        it('generates valid address', function() {
          const a = CardanoCrypto.Redemption.redemptionKeyToAddress(redemptionKey, cfg.protocol_magic);
          const [tagged, checksum] = cbor.decode(Buffer.from(a));
          expect(crc.crc32(tagged.value)).equal(checksum);
        });

        it('creates address matching expected', function() {
          const a = CardanoCrypto.Redemption.redemptionKeyToAddress(redemptionKey, cfg.protocol_magic);
          expect(bs58.encode(Buffer.from(a))).equal(expectedAddress)
        });

        it('generates valid transaction', function () {
          const address = CardanoCrypto.Redemption.redemptionKeyToAddress(redemptionKey, cfg.protocol_magic);
          const input = { id: txId, index: txOutIndex };
          const output = { address: bs58.encode(Buffer.from(address)), value: JSON.stringify(coinValue) };
          const { result: { cbor_encoded_tx } } = CardanoCrypto.Redemption.createRedemptionTransaction(redemptionKey, input, output, cfg.protocol_magic);

          // destruct result transaction
          const [[resultInputs, resultOutputs, attributes], resultWitnesses] = cbor.decode(Buffer.from(cbor_encoded_tx));

          // validate inputs
          expect(resultInputs.length).equal(1);
          expect(resultInputs[0].length).equal(2);
          const [[intputType, inputTagged]] = resultInputs;
          expect(intputType).equal(0);
          const [inputId, inputIndex] = cbor.decode(inputTagged.value);
          expect(inputIndex).equal(txOutIndex);
          expect(inputId).deep.equal(txId);

          // validate outputs
          expect(resultInputs.length).equal(1);
          expect(resultInputs[0].length).equal(2);
          const [[outputAddress, outputValue]] = resultOutputs;
          expect(cbor.encode(outputAddress)).deep.equal(address);
          expect(outputValue).equal(coinValue);

          // validate witness
          expect(resultWitnesses.length).equal(1);
          expect(resultWitnesses[0].length).equal(2);
          const [[witnessType, witnessTagged]] = resultWitnesses;
          expect(witnessType).equal(2);
          const [witnessPub, witnessSign] = cbor.decode(witnessTagged.value);
          expect(witnessPub.toString('hex'))
            .equal(expectedPublicKey);
          expect(witnessSign.toString('hex'))
            .equal(expectedSignature);
        });
    });
};

describe('Test redemption', function() {
  for (let i = 0; i < TEST_VECTORS.length; i++) {
    mkTest(i);
  }
});
