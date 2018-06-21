const loadModule = import("wallet-wasm2/wallet_wasm2.js");

loadModule.then(Cardano => {
    const MNEMONICS = "town refuse ribbon antenna average enough crumble ice fashion giant question glance";
    const PATH      = [0x8000000, 0x8000000];

    console.log("retrieving root_xprv from a daedalus mnemonic", MNEMONICS);
    let root_xprv = Cardano.XPrv.from_daedalus_mnemonics(MNEMONICS);
    let root_xpub = root_xprv.public();

    console.log("daedalus derivation from derivation path", PATH);
    let xprv = root_xprv;
    PATH.forEach(index => xprv = xprv.derive_v1(index));
    let xpub = xprv.public();
    console.log("daedalus payload");
    let payload = Cardano.Payload.new(root_xpub, PATH);

    let addr = xpub.to_adddress_with_payload(payload);
    console.log("Daedalus Address", addr.to_base58());
});
