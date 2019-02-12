const expect = require('chai').expect;
const CardanoCrypto = require('../../dist/index.js');
const bs58 = require('bs58');
const cbor = require('cbor');
const crc = require('crc');

const TEST_VECTORS = [
  {
    iohkRedemptionPubKey: 'URVk8FxX6Ik9z-Cub09oOxMkp6FwNq27kJUXbjJnfsQ=',
    expectedIohkRedemptionAddress: 'Ae2tdPwUPEZKQuZh2UndEoTKEakMYHGNjJVYmNZgJk2qqgHouxDsA5oT83n',
    expectedIohkRedemptionInputTx: '0ae3da29711600e94a33fb7441d2e76876a9a1e98b5ebdefbf2e3bc535617616',
    redemptionKey: Buffer.from('qXQWDxI3JrlFRtC4SeQjeGzLbVXWBomYPbNO1Vfm1T4=', 'base64'),
    expectedAddress: 'Ae2tdPwUPEZB9sRkyXbcVMNa4pwFzzmxP4WkX88bMduUgusn26UzCtyCr42',
    expectedPublicKey: '5a67cee38877909eab7d19de36cb8537bb102d9952d107ced2bfedfd823b0d34',
    expectedSignature: '5a9347569f43e2eba196ab3403a699e74232127dc6ffe712fde0d052d6abf705291b019842b1137a3ba8198abf6925c8b79c7989cc8f78556ed36fa4ab3a2e08',
    txId: new Uint8Array([0xaa,0xd7,0x8a,0x13,0xb5,0x0a,0x01,0x4a,0x24,0x63,0x3c,0x7d,0x44,0xfd,0x8f,0x8d,0x18,0xf6,0x7b,0xbb,0x3f,0xa9,0xcb,0xce,0xdf,0x83,0x4a,0xc8,0x99,0x75,0x9d,0xcd]),
    txOutIndex: 1,
    coinValue: 12345678
  }
];

let mkTest = (i) => {
    const {
      iohkRedemptionPubKey,
      expectedIohkRedemptionAddress,
      expectedIohkRedemptionInputTx,
      redemptionKey,
      expectedAddress,
      expectedPublicKey,
      expectedSignature,
      txId,
      txOutIndex,
      coinValue
    } = TEST_VECTORS[i];
    const cfg = CardanoCrypto.Config.defaultConfig();

    describe('Test ' + i, function() {
        before(async () => {
            await CardanoCrypto.loadRustModule()
        });

        it('generates valid avvm tx from public', function () {
          const { result: { tx_id, address } } = CardanoCrypto.Redemption.redemptionPubKeyToAvvmTxOut(
            Buffer.from(iohkRedemptionPubKey, 'base64'),
            cfg.protocol_magic);
          const addressStr = bs58.encode(Buffer.from(address));
          expect(addressStr).equal(expectedIohkRedemptionAddress);
          expect(tx_id).equal(expectedIohkRedemptionInputTx);
        });

        it('generates valid address from private', function() {
          const a = CardanoCrypto.Redemption.redemptionKeyToAddress(redemptionKey, cfg.protocol_magic);
          const [tagged, checksum] = cbor.decode(Buffer.from(a));
          expect(crc.crc32(tagged.value)).equal(checksum);
        });

        it('creates address from private matching expected', function() {
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
