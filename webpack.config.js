const path = require('path');
const webpack = require('webpack');
const CopyPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

// Polyfill fallbacks shared by both entries.
const fallback = {
  assert: require.resolve('assert/'),
  buffer: require.resolve('buffer/'),
  crypto: require.resolve('crypto-browserify'),
  events: require.resolve('events/'),
  http: require.resolve('stream-http'),
  https: require.resolve('https-browserify'),
  os: require.resolve('os-browserify/browser'),
  path: require.resolve('path-browserify'),
  querystring: require.resolve('querystring-es3'),
  stream: require.resolve('stream-browserify'),
  url: require.resolve('url/'),
  util: require.resolve('util/'),
  vm: require.resolve('vm-browserify'),
  zlib: require.resolve('browserify-zlib'),
  fs: false,
  net: false,
  tls: false,
  child_process: false,
  dns: false,
};

const alias = {
  // WalletConnect ESM bundles reference 'process/browser' without extension;
  // webpack 5 strict ESM mode requires a fully-specified path.
  'process/browser': path.resolve(__dirname, 'node_modules/process/browser.js'),
};

const provide = new webpack.ProvidePlugin({
  Buffer: ['buffer', 'Buffer'],
  process: 'process/browser',
});

module.exports = (env, argv) => {
  const isDev = argv.mode === 'development';

  // ── Popup (browser page — target: web) ───────────────────────────────────
  const popupConfig = {
    name: 'popup',
    target: 'web',
    entry: { popup: './src/popup/popup.js' },
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: '[name].js',
    },
    module: {
      rules: [
        {
          test: /\.css$/,
          use: [MiniCssExtractPlugin.loader, 'css-loader'],
        },
      ],
    },
    plugins: [
      provide,
      new HtmlWebpackPlugin({
        template: './src/popup/popup.html',
        filename: 'popup.html',
        chunks: ['popup'],
        inject: 'body',
      }),
      new MiniCssExtractPlugin({ filename: '[name].css' }),
    ],
    resolve: { alias, fallback },
    devtool: isDev ? 'inline-source-map' : false,
    performance: { hints: false },
    stats: { warnings: false },
  };

  // ── Background service worker (target: webworker) ────────────────────────
  //
  // Using target:'webworker' is critical: webpack generates code that uses
  // `self` (not `window`) as the global object.  In a MV3 service worker
  // `window` is undefined, so a `target:'web'` build causes any code that
  // touches window.crypto, window.WebSocket etc. to silently fail — which is
  // why Web3Wallet.init() never resolves.
  const backgroundConfig = {
    name: 'background',
    target: 'webworker',
    entry: { background: './src/background/background.js' },
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: '[name].js',
    },
    plugins: [
      provide,
      new CopyPlugin({
        patterns: [
          { from: 'manifest.json', to: 'manifest.json' },
          { from: 'icons', to: 'icons', noErrorOnMissing: true },
        ],
      }),
    ],
    resolve: { alias, fallback },
    devtool: isDev ? 'inline-source-map' : false,
    performance: { hints: false },
    stats: { warnings: false },
  };

  return [backgroundConfig, popupConfig];
};
