// Note that a dynamic `import` statement here is required due to
// webpack/webpack#6615, but in theory `import { greet } from './hello_world';`
// will work here one day as well!
const Wallet = import('cardano-wallet');

import { TextEncoder, TextDecoder } from 'text-encoder';
import cryptoRandomString from 'crypto-random-string';

// patch missing functions
var util = require('util');
util.TextEncoder = TextEncoder;
util.TextDecoder = TextDecoder;

let RustWallet = null;

Wallet
  .then(Wallet => {
    const MNEMONICS = "crowd captain hungry tray powder motor coast oppose month shed parent mystery torch resemble index";
    const MNEMONIC_PASSWORD = "Cardano Rust for the winners!";
    const SPENDING_PASSWORD = 'Cardano Rust for all!';

    let settings = Wallet.BlockchainSettings.mainnet();

    let entropy = Wallet.Entropy.from_english_mnemonics(MNEMONICS);
    let wallet = Wallet.Bip44RootPrivateKey.recover(entropy, MNEMONIC_PASSWORD);
    const master_key =  wallet.key().to_hex();
    console.log('master key: ' + master_key);

    // encrypt / decrypt example
    {
      const salt = Buffer.from(cryptoRandomString(2 * 32), 'hex');
      const nonce = Buffer.from(cryptoRandomString(2 * 12), 'hex');
      const encoded_key = Buffer.from(master_key, 'hex');
      const encrypted_key = Wallet.password_encrypt(SPENDING_PASSWORD, salt, nonce, encoded_key);
      console.log('encrypted master key: ' + Buffer.from(encrypted_key).toString('hex'));

      const decrypted_key = Wallet.password_decrypt(SPENDING_PASSWORD, encrypted_key);
      const decrypted_key_hex =Buffer.from(decrypted_key).toString('hex');
      console.log('decrypted master key: ' + decrypted_key_hex);
    }

    let account = wallet.bip44_account(Wallet.AccountIndex.new(0 | 0x80000000));
    console.log('account private ' + account.key().to_hex());
    let account_public = account.public();
    console.log('account public ' + account_public.key().to_hex());

    let chain_prv = account.bip44_chain(false);
    let key_prv = chain_prv.address_key(Wallet.AddressKeyIndex.new(0));
    console.log('address public ' + key_prv.to_hex());
    let chain_pub = account_public.bip44_chain(false);
    let key_pub = chain_pub.address_key(Wallet.AddressKeyIndex.new(0));
    console.log('address public ' + key_pub.to_hex());

    let address = key_pub.bootstrap_era_address(settings);

    console.log("Address m/bip44/ada/'0/0/0", address.to_base58());

    // Building a transaction

    let transaction_builder = new Wallet.TransactionBuilder();

    const inputs = [
      { pointer: { id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", index: 1 }, value: 1 },
      { pointer: { id: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", index: 0 }, value: 1 }
    ];
    const outputs = [
      // TODO: you can test the balance by changing the value here.
      { address: "Ae2tdPwUPEZCEhYAUVU7evPfQCJjyuwM6n81x6hSjU9TBMSy2YwZEVydssL", value: "1826205" }
    ];

    for (let index = 0; index < inputs.length; index++) {
      const pointer = Wallet.TxoPointer.from_json(inputs[index].pointer);
      const value = Wallet.Coin.from(inputs[index].value, 0);
      transaction_builder.add_input(pointer, value);
    }

    console.log("all inputs set...", transaction_builder.get_input_total().to_str());

    for (let index = 0; index < outputs.length; index++) {
      const txout = Wallet.TxOut.from_json(outputs[index]);
      transaction_builder.add_output(txout);
    }

    console.log("all outputs set...", transaction_builder.get_output_total().to_str());

    // verify the balance and the fees:
    const fee_algorithm = Wallet.LinearFeeAlgorithm.default();
    const balance = transaction_builder.get_balance(fee_algorithm);
    if (balance.is_negative()) {
      console.error("not enough inputs, ", balance.value().to_str());
      throw Error("Not enough inputs");
    } else {
      if (balance.is_zero()) {
        console.info("Perfect balance no dust");
      } else {
        console.warn("Loosing some coins in extra fees: ", balance.value().to_str());
      }
    }

    let transaction = transaction_builder.make_transaction();

    console.log("unsigned transaction built");

    let transaction_finalizer = new Wallet.TransactionFinalized(transaction);

    console.log("transaction finalizer built", transaction_finalizer);

    for (let index = 0; index < inputs.length; index++) {
      const witness = Wallet.Witness.new_extended_key(
        settings,
        key_prv,
        transaction_finalizer.id()
      );
      transaction_finalizer.add_witness(witness);
      console.log("signature ", index, "added");

    }

    // at this stage the transaction is ready to be sent
    const signed_transaction = transaction_finalizer.finalize();
    console.log("ready to send transaction: ", signed_transaction.to_hex());
    console.log(signed_transaction.to_json());

  })
  .catch(console.error);
