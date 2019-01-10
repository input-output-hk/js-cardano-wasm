// Note that a dynamic `import` statement here is required due to
// webpack/webpack#6615, but in theory `import { greet } from './hello_world';`
// will work here one day as well!
const Wallet = import('cardano-wallet');

let RustWallet = null;

Wallet
  .then(Wallet => {
    console.log("loaded...");

    const MNEMONICS = "crowd captain hungry tray powder motor coast oppose month shed parent mystery torch resemble index";
    const PASSWORD = "Cardano Rust for the winners!";

    let settings = Wallet.BlockchainSettings.mainnet();

    let entropy = Wallet.Entropy.from_english_mnemonics(MNEMONICS);
    let wallet = Wallet.Bip44RootPrivateKey.recover(entropy, PASSWORD);

    let account = wallet.bip44_account(Wallet.AccountIndex.new(0 | 0x80000000));
    let account_public = account.public();

    let key_prv = account.address_key(false, Wallet.AddressKeyIndex.new(0));
    let key_pub = account_public.address_key(false, Wallet.AddressKeyIndex.new(0));

    let address = key_pub.bootstrap_era_address(settings);

    console.log("Address m/bip44/ada/'0/0/0", address.to_base58());
  })
  .catch(console.error);
