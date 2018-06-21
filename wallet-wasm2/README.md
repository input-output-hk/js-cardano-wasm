# Wallet Wasm (using wasm-bindgen)

This is an experimental js/wasm/rust binding of
[cardano-rust](https://github.com/input-output-hk/rust-cardano)'s `wallet-crypto`
crate. It uses the binding generator tool
[`wasm-bindgen`](https://github.com/rustwasm/wasm-bindgen) and
[`wasm-pack`](https://github.com/rustwasm/wasm-pack).

## Generate npm package

We use `wasm-pack` to generate a NPM package:

1. [install `rustup`](https://www.rust-lang.org/en-US/install.html):
   ```
   $ curl https://sh.rustup.rs -sSf | sh
   ```
2. install `wasm-pack`:
   ```
   $ cargo install wasm-pack
   ```
3. generate it all:
   ```
   $ wasm-pack init .
   ```

## Example

see [js-test](./js-test) for an example of use:

```
$ cd js-test
$ npm install
$ npm run serve
```

open your browser to: http://localhost:8080/index.html and look at the JSON logs.

## features

Here we strive to remove some of the hand-written functions that came with limitations
regarding: allocating more memory than needed for output, using JSON
RPC style...

Instead, we expose a collection of objects:

- private key;
- public key;
- payload;

```js
const loadModule = import('wallet-wasm2/wallet_wasm2.js');

loadModule.then(Cardano => {
    const MNEMONICS = "town refuse ribbon antenna average enough crumble ice fashion giant question glance";

    // retrieve a root private key
    let root_xprv = Cardano.XPrv.from_daedalus_mnemonics(MNEMONICS);
});
```
