import loadModule from './wallet';

let Module = null;

console.log(loadModule);

// Ensure we are only creating a single instance of the web assembly module
export const loadRustModule = () => Module ?
  Promise.resolve(Module)
  :
  loadModule.then(module => {
    console.log(module);
    Module = module;
    return Module;
  }
);

// Expose the WASM module as default export
let Cardano = {};
loadRustModule().then((module) => Object.assign(Cardano, module));
export default Cardano;
