const path = require('path');

module.exports = {
  entry: "./js/index.js",
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "index.js",
    library: 'Cardano',
    libraryTarget: 'umd',
  },
  mode: "development",
  module: {
    rules: [
      {
        test: /\.js$/,
        use: {
          loader: 'babel-loader',
          options: {
            cacheDirectory: true,
          }
        },
      },
      {
        test: /\.wasm$/,
        use: 'wasm-loader'
      }
    ]
  },
};
