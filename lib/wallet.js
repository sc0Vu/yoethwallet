const ethUtil = require('ethereumjs-util');
const randomBytes = require('randombytes');
const scrypt = require('scrypt-async');
const bip39 = require('bip39');
const wordlist = bip39.wordlists.EN;
const wallet = {};

let keystore = function (privateKey) {
  if (!privateKey) {
    throw new Error('Please enter private key.');
  }
  if (!ethUtil.isValidPrivate(privateKey)) {
    throw new Error('Private key is invalid.');
  }
  this._privateKey = privateKey;
  this._publicKey = ethUtil.privateToPublic(privateKey);
};

wallet.validateSeed = function (seed) {
  if (typeof seed !== 'string') {
    return false;
  }
  return bip39.validateMnemonic(seed, wordlist);
};

wallet.generate = function (randomSeed, hdPath, callback) {
  randomBytes(32, function (err, rand) {
    if (err) {
      callback(err, null);
      return;
    }

    try {
      callback(null, new keystore(rand));
    } catch (err) {
      callback(err, null);
    }
  });
};

wallet.fromPrivateKey = function (privateKey, callback) {
  try {
    callback(null, new keystore(privateKey));
  } catch (err) {
    callback(err, null);
  }
}

Object.defineProperty(keystore.prototype, 'privateKey', {
  get: function () {
    return this._privateKey;
  },
});

Object.defineProperty(keystore.prototype, 'publicKey', {
  get: function () {
    return this._publicKey;
  },
});

keystore.prototype.getAddress = function () {
  return ethUtil.publicToAddress(this._publicKey);
};

keystore.prototype.getHexAddress = function (withPrefix) {
  if (withPrefix) {
   return '0x' + this.getAddress().toString('hex');
  }
  return this.getAddress().toString('hex');
}

keystore.prototype.getFilename = function () {
  const date = new Date;

  return [
    'UTC--',
    date.toJSON().replace(/:/g, '-'),
    '--',
    this.getHexAddress()
  ].join('');
};

keystore.prototype.toJson = function (password, opts) {
  return master.toV3String(password, opts);
};

keystore.prototype.getPrivateKey = function () {
  return this._privateKey;
};

keystore.prototype.getHexPrivateKey = function () {
  return this._privateKey.toString('hex');
};

keystore.prototype.getPublicKey = function () {
  return this._publicKey;
};

keystore.prototype.getHexPublicKey = function () {
  return this._publicKey.toString('hex');
};

module.exports = exports = wallet;
