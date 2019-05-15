# Cardano Wallet

This is a new version of the Cardano Wasm binding for Icarus/Yoroi.
It exposes everything one needs to be able to build a cardano wallet
in javascript.

# How to install

```
npm i --save cardano-wallet
```

# How to use

You can seek documentation
[here](https://github.com/rustwasm/create-wasm-app#create-wasm-app)
regarding how to use this package in your project.

Now remember, with great power comes great responsibility. You can now
write a cardano wallet, redeem your certificates, create and sign
transactions.

## Example on how to retrieve a wallet from mnemonics

The example below shows you how to create/retrieve a wallet from
the mnemonics and the password.

```js
import * as Cardano from "cardano-wallet";

const MNEMONICS = "crowd captain hungry tray powder motor coast oppose month shed parent mystery torch resemble index";
const PASSWORD = "Cardano Rust for the winners!";

// to connect the wallet to mainnet
let settings = Cardano.BlockchainSettings.mainnet();

// recover the entropy
let entropy = Cardano.Entropy.from_english_mnemonics(MNEMONICS);
// recover the wallet
let wallet = Cardano.Bip44RootPrivateKey.recover(entropy, PASSWORD);

// create a wallet account
let account = wallet.bip44_account(Cardano.AccountIndex.new(0 | 0x80000000));
let account_public = account.public();

// create an address
let chain_pub = account_public.bip44_chain(false);
let key_pub = chain_pub.address_key(Cardano.AddressKeyIndex.new(0));
let address = key_pub.bootstrap_era_address(settings);

console.log("Address m/bip44/ada/'0/0/0", address.to_base58());
```

## Create a transaction:

The example below shows how to create a transaction, this transaction is not
ready to be sent through the network. It shows that there is separation of
concerns between the transaction you build/prepare and signing the transaction
in the last example.

```js
// assuming the xprv and the settings from the example above are available in this scope

const inputs = [
    { pointer: { id: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", index: 1 }, value: 1 },
    { pointer: { id: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", index: 0 }, value: 1 }
];
const outputs = [
    { address: "Ae2tdPwUPEZCEhYAUVU7evPfQCJjyuwM6n81x6hSjU9TBMSy2YwZEVydssL", value: "1826205" }
];

// the fee algorithm (i.e. the function to compute the fees of a transaction)
const fee_algorithm = Wallet.LinearFeeAlgorithm.default();

let transaction_builder = new Wallet.TransactionBuilder();

for (let index = 0; index < inputs.length; index++) {
    const pointer = Wallet.TxoPointer.from_json(inputs[index].pointer);
    const value = Wallet.Coin.from(inputs[index].value, 0);
    transaction_builder.add_input(pointer, value);
}

for (let index = 0; index < outputs.length; index++) {
    const txout = Wallet.TxOut.from_json(outputs[index]);
    transaction_builder.add_output(txout);
}

// verify the balance and the fees:
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

// Warning: this function does not throw exception if the transaction is not
// balanced. This is your job to make sure your transaction's inputs and outputs
// and fees are balanced.
let transaction = transaction_builder.make_transaction();
```

## Signing a transaction

This function shows how to sign a transaction so it can be accepted by the
network.

You need to make sure:

1. the key_prv correspond to the private key associated to the address for the given
   input (see UTxO based crypto-currency model/documentations);
2. the signatures are added in the same order the inputs of this transaction
   were added.

```js
// retrieve the prepared transaction from the previous example
let transaction_finalizer = new Wallet.TransactionFinalized(transaction);

for (let index = 0; index < inputs.length; index++) {
    const witness = Wallet.Witness.new_extended_key(
        settings,
        key_prv,
        transaction_finalizer.id()
    );
    transaction_finalizer.add_witness(witness);
}

// at this stage the transaction is ready to be sent
const signed_transaction = transaction_finalizer.finalize();
console.log("ready to send transaction: ", signed_transaction.to_hex());
console.log(signed_transaction.to_json());
```
