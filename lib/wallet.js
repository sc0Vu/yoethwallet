const ethWallet = require('ethereumjs-wallet');
const hdkey = require('ethereumjs-wallet/hdkey');
const bip39 = require('bip39');

const defaultHdPath = 'm/44\'/60\'/0\'/0';
const wallet = {};
let master = {};
let keystore = {};

wallet.generate = function (randomSeed, hdPath) {
  if (!this.validateSeed(randomSeed)) {
    randomSeed = bip39.generateMnemonic();
  }
  const path = (hdPath) || defaultHdPath;

  keystore = hdkey.fromMasterSeed(randomSeed);
  keystore.derivePath(path);
  master = keystore.getWallet();
};

wallet.validateSeed = function (seed) {
  if (typeof seed !== 'string') {
    return false;
  }
  return bip39.validateMnemonic(randomSeed);
};

wallet.getFilename = function () {
  return master.getV3Filename();
};

wallet.toJson = function (password) {
  return master.toV3String(password);
};

wallet.getPrivateKey = function () {
  return master.getPrivateKey().toString('hex');
};

wallet.getPublicKey = function () {
  return master.getPublicKey().toString('hex');
};

wallet.getAddress = function () {
  return `0x${master.getAddress().toString('hex')}`;
};

wallet.fromJson = function (input, password) {
  master = ethWallet.fromV3(input, password);
};

module.exports = exports = wallet;
