const ethUtil = require('ethereumjs-util');
const crypto = require('crypto');
const scrypt = require('scrypt-async');
const uuid = require('uuid');
const util = require('./util');

const keystore = function (privateKey) {
  if (!privateKey) {
    throw new Error('Please enter private key.');
  }
  if (!ethUtil.isValidPrivate(privateKey)) {
    throw new Error('Private key is invalid.');
  }
  this._privateKey = privateKey;
  this._publicKey = ethUtil.privateToPublic(privateKey);
};

Object.defineProperty(keystore.prototype, 'privateKey', {
  get() {
    return this._privateKey;
  },
});

Object.defineProperty(keystore.prototype, 'publicKey', {
  get() {
    return this._publicKey;
  },
});

Object.defineProperty(keystore.prototype, 'hdKey', {
  get() {
    return this._hdKey;
  },
  set(hdKey) {
    this._hdKey = hdKey;
  },
});

keystore.prototype.getAddress = function () {
  return ethUtil.publicToAddress(this._publicKey);
};

keystore.prototype.getHexAddress = function (withPrefix) {
  if (withPrefix) {
    return `0x${this.getAddress().toString('hex')}`;
  }
  return this.getAddress().toString('hex');
};

keystore.prototype.getV3Filename = function () {
  const date = new Date();

  return [
    'UTC--',
    date.toJSON().replace(/:/g, '-'),
    '--',
    this.getHexAddress(),
  ].join('');
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

keystore.prototype.toV3String = function (password, options, callback) {
  this.toV3(password, options, (err, v3) => {
    if (err) {
      callback(err, null);
      return;
    }
    callback(null, JSON.stringify(v3));
  });
};

// see https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition/b66dfbe3e84287f6fa61c079007255270cd20c14
keystore.prototype.toV3 = function (password, options, callback) {
  try {
    if (!this._privateKey) {
      throw new Error('Please generate wallet with private key.');
    }

    options = options || {};

    const cipherAlgorithm = options.cipher || 'aes-128-ctr';
    const salt = options.salt || crypto.randomBytes(32);
    const iv = options.iv || crypto.randomBytes(16);
    const id = uuid.v4({ random: options.uuid || crypto.randomBytes(16) });
    const kdf = options.kdf || 'scrypt';
    const kdfparams = {
      dklen: options.dklen || 32,
      salt: salt.toString('hex'),
    };
    const cb = function (derivedKey) {
      derivedKey = new Buffer(derivedKey);

      const cipher = crypto.createCipheriv(cipherAlgorithm, derivedKey.slice(0, 16), iv);

      if (!cipher) {
        callback(new Error('Unsupported cipher algorithm.'), null);
        return;
      }

      const ciphertext = Buffer.concat([cipher.update(this._privateKey), cipher.final()]);
      const mac = ethUtil.sha3(Buffer.concat([derivedKey.slice(16, 32), new Buffer(ciphertext, 'hex')]));

      const v3 = {
        version: 3,
        id,
        address: this.getHexAddress(),
        crypto: {
          ciphertext: ciphertext.toString('hex'),
          cipherparams: {
            iv: iv.toString('hex'),
          },
          cipher: cipherAlgorithm,
          kdf,
          kdfparams,
          mac: mac.toString('hex'),
        },
      };

      callback(null, v3);
    }.bind(this);

    if (kdf === 'pbkdf2') {
      kdfparams.c = options.c || 262144;
      kdfparams.prf = 'hmac-sha256';
      crypto.pbkdf2(new Buffer(password), salt, kdfparams.c, kdfparams.dklen, 'sha256', (err, derivedKey) => {
        if (err) {
          callback(err, null);
          return;
        }
        cb(derivedKey);
      });
    } else if (kdf === 'scrypt') {
      const saltUse = util.bufferToArray(salt);

      kdfparams.n = options.n || 262144;
      kdfparams.r = options.r || 8;
      kdfparams.p = options.p || 1;

      scrypt(password, salt, {
        N: kdfparams.n, r: kdfparams.r, p: kdfparams.p, dklen: kdfparams.dklen, encoding: 'binary',
      }, cb);
    } else {
      throw new Error('Unsupported key derivation function.');
    }
  } catch (err) {
    callback(err, null);
  }
};

module.exports = keystore;
