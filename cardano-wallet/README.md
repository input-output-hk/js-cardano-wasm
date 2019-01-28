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
let key_pub = account_public.address_key(false, Cardano.AddressKeyIndex.new(0));
let address = key_pub.bootstrap_era_address(settings);

console.log("Address m/bip44/ada/'0/0/0", address.to_base58());
```
