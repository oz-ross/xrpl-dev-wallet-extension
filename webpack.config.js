const path = require('path');
const webpack = require('webpack');
const CopyPlugin = require('copy-webpack-plugin');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = (env, argv) => {
  const isDev = argv.mode === 'development';

  return {
    entry: {
      popup: './src/popup/popup.js',
      background: './src/background/background.js',
    },
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: '[name].js',
      clean: true,
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
      new webpack.ProvidePlugin({
        Buffer: ['buffer', 'Buffer'],
        process: 'process/browser',
      }),
      new HtmlWebpackPlugin({
        template: './src/popup/popup.html',
        filename: 'popup.html',
        chunks: ['popup'],
        inject: 'body',
      }),
      new MiniCssExtractPlugin({
        filename: '[name].css',
      }),
      new CopyPlugin({
        patterns: [
          { from: 'manifest.json', to: 'manifest.json' },
          { from: 'icons', to: 'icons', noErrorOnMissing: true },
        ],
      }),
    ],
    resolve: {
      alias: {
        // WalletConnect ESM bundles reference 'process/browser' without extension;
        // webpack 5 strict ESM mode requires a fully-specified path.
        'process/browser': path.resolve(__dirname, 'node_modules/process/browser.js'),
      },
      fallback: {
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
        // Not needed in browser
        fs: false,
        net: false,
        tls: false,
        child_process: false,
        dns: false,
      },
    },
    devtool: isDev ? 'inline-source-map' : false,
    // Suppress warnings from large dependency bundles
    performance: { hints: false },
    stats: { warnings: false },
  };
};
