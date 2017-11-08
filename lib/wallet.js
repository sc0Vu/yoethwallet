const ethWallet = require('ethereumjs-wallet');
const hdkey = require('ethereumjs-wallet/hdkey');
const bip39 = require('bip39');
const randomBytes = require('randombytes');

const defaultHdPath = 'm/44\'/60\'/0\'/0';
const wallet = {};
const wordlist = bip39.wordlists.EN;
let master = {};
let keystore = {};

wallet.generate = function (randomSeed, hdPath) {
  if (!this.validateSeed(randomSeed, wordlist)) {
    randomSeed = bip39.generateMnemonic(128, randomBytes, wordlist);
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
  return bip39.validateMnemonic(seed, wordlist);
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

wallet.getPrivateKeyBuffer = function () {
  return master.getPrivateKey();
};

wallet.getPublicKey = function () {
  return master.getPublicKey().toString('hex');
};

wallet.getPublicKeyBuffer = function () {
  return master.getPublicKey();
};

wallet.getAddress = function () {
  return `0x${master.getAddress().toString('hex')}`;
};

wallet.fromJson = function (input, password) {
  master = ethWallet.fromV3(input, password);
};

module.exports = exports = wallet;
