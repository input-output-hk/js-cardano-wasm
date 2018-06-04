# cardano wasm binding for JavaScript

This library provides rust binding for wasm and generates the JS bindings from wasm
using rust's [wasm-bindgen](https://crates.io/crates/wasm-bindgen).

## Installation

### You will need to install rust's compiler

```
# install rustup
curl https://sh.rustup.rs -sSf | sh
# use nightly version
rustup install nightly
rustup target add wasm32-unknown-unknown --toolchain nightly
```

### You will need to install rust's wasm-bindgen

```
cargo install wasm-bindgen
```

## Build the Library

To Compile the rust crypto to a Web Assembly (WASM) module and build JS library run:

```
npm install
npm build
```

to test the library:

```
npm build-test
npm test
```

# Notes

The rust code contains `rwc/` a fork of [rust-crypto](https://github.com/DaGenix/rust-crypto)
without the dependencies that cannot be build easily in a wasm environment, and minus the
algorithms that are not useful.
