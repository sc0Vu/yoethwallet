const ethUtil = require('ethereumjs-util');
const crypto = require('crypto');
const scrypt = require('scrypt-async');
const uuid = require('uuid');
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
  crypto.randomBytes(32, function (err, rand) {
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

// wallet.fromV3 = function (password, options, callback) {}

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

keystore.prototype.toV3String = function (password, options, callback) {
  this.toV3(password, options, function (err, v3) {
    if (err) {
      callback(err, null);
      return;
    }
    callback(null, JSON.stringify(v3));
  });
};

// see https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition/b66dfbe3e84287f6fa61c079007255270cd20c14
keystore.prototype.toV3 = function (password, opts, callback) {
  try {
    if (!this._privateKey) {
      throw new Error('Please generate wallet with private key.');
    }

    opts = opts || {};
    const salt = opts.salt || crypto.randomBytes(32);
    const iv = opts.iv || crypto.randomBytes(16);
    const id = uuid.v4({ random: opts.uuid || crypto.randomBytes(16) });

    let derivedKey;
    let kdf = opts.kdf || 'scrypt';
    let kdfparams = {
      dklen: opts.dklen || 32,
      salt: salt.toString('hex'),
    };
    let cb = function (derivedKey) {
      derivedKey = new Buffer(derivedKey);

      let cipher = crypto.createCipheriv(opts.cipher || 'aes-128-ctr', derivedKey.slice(0, 16), iv);

      if (!cipher) {
        callback(new Error('Unsupported cipher'), null);
        return;
      }

      let ciphertext = Buffer.concat([ cipher.update(this.privateKey), cipher.final() ]);
      let mac = ethUtil.sha3(Buffer.concat([ derivedKey.slice(16, 32), new Buffer(ciphertext, 'hex') ]));

      const v3 = {
        version: 3,
        id: id,
        address: this.getHexAddress(),
        crypto: {
          ciphertext: ciphertext.toString('hex'),
          cipherparams: {
            iv: iv.toString('hex'),
          },
          cipher: opts.cipher || 'aes-128-ctr',
          kdf: kdf,
          kdfparams: kdfparams,
          mac: mac.toString('hex'),
        },
      };

      callback(null, v3);
    }.bind(this);

    if (kdf === 'pbkdf2') {
      kdfparams.c = opts.c || 262144;
      kdfparams.prf = 'hmac-sha256';
      crypto.pbkdf2(new Buffer(password), salt, kdfparams.c, kdfparams.dklen, 'sha256', function (err, derivedKey) {
        if (err) {
          callback(err, null);
          return;
        }
        cb(derivedKey);
      });
    } else if (kdf === 'scrypt') {
      kdfparams.n = opts.n || 262144;
      kdfparams.r = opts.r || 8;
      kdfparams.p = opts.p || 1;

      scrypt(password, salt, Object.assign({N: kdfparams.n}, kdfparams), cb);
    } else {
      throw new Error('Unsupported kdf');
    }
  } catch (err) {
    callback(err, null);
  }
};

module.exports = exports = wallet;
