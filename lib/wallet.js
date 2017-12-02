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
};

wallet.fromV3String = function (v3String, password, callback) {
  try {
    const v3 = JSON.parse(v3String);

    this.fromV3(v3, password, callback);
  } catch (err) {
    callback(err, null);
  }
};

wallet.fromV3 = function (v3, password, callback) {
  try {
    if (v3.version !== 3) {
      throw new Error('Not a V3 wallet.');
    }

    const cb = function (derivedKey) {
      derivedKey = new Buffer(derivedKey);

      const ciphertext = new Buffer(v3.crypto.ciphertext, 'hex');
      const mac = ethUtil.sha3(Buffer.concat([ derivedKey.slice(16, 32), ciphertext ]));

      if (mac.toString('hex') !== v3.crypto.mac) {
        console.log(mac.toString('hex'), v3.crypto.mac);
        callback(new Error('Key derivation failed.'), null);
      }

      let decipher = crypto.createDecipheriv(v3.crypto.cipher, derivedKey.slice(0, 16), new Buffer(v3.crypto.cipherparams.iv, 'hex'));
      const seed = Buffer.concat([ decipher.update(ciphertext), decipher.final() ]);

      callback(null, new keystore(seed));
    };

    if (v3.crypto.kdf === 'scrypt') {
      const kdfparams = v3.crypto.kdfparams;
      const saltBuffer = new Buffer(kdfparams.salt, 'hex');

      let salt = [];

      for (let i=0; i<saltBuffer.length; i++) {
        salt.push(saltBuffer[i]);
      }

      scrypt(password, salt, {N: kdfparams.n, r: kdfparams.r, p: kdfparams.p, dklen: kdfparams.dklen, encoding: 'binary'}, cb);
    } else if (v3.crypto.kdf === 'pbkdf2') {
      const kdfparams = v3.crypto.kdfparams;

      if (kdfparams.prf !== 'hmac-sha256') {
        throw new Error('PBKDF2 prf must be hmac-sha256.');
      }

      crypto.pbkdf2(new Buffer(password), new Buffer(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256', function (err, derivedKey) {
        if (err) {
          callback(err, null);
          return;
        }
        cb(derivedKey);
      });
    } else {
      throw new Error('Unsupported key derivation scheme.');
    }
  } catch (err) {
    callback(err, null);
  }
};

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
};

keystore.prototype.getV3Filename = function () {
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

      let cipher = crypto.createCipheriv(cipherAlgorithm, derivedKey.slice(0, 16), iv);

      if (!cipher) {
        callback(new Error('Unsupported cipher algorithm.'), null);
        return;
      }

      const ciphertext = Buffer.concat([ cipher.update(this.privateKey), cipher.final() ]);
      const mac = ethUtil.sha3(Buffer.concat([ derivedKey.slice(16, 32), new Buffer(ciphertext, 'hex') ]));

      const v3 = {
        version: 3,
        id: id,
        address: this.getHexAddress(),
        crypto: {
          ciphertext: ciphertext.toString('hex'),
          cipherparams: {
            iv: iv.toString('hex'),
          },
          cipher: cipherAlgorithm,
          kdf: kdf,
          kdfparams: kdfparams,
          mac: mac.toString('hex'),
        },
      };

      callback(null, v3);
    }.bind(this);

    if (kdf === 'pbkdf2') {
      kdfparams.c = options.c || 262144;
      kdfparams.prf = 'hmac-sha256';
      crypto.pbkdf2(new Buffer(password), salt, kdfparams.c, kdfparams.dklen, 'sha256', function (err, derivedKey) {
        if (err) {
          callback(err, null);
          return;
        }
        cb(derivedKey);
      });
    } else if (kdf === 'scrypt') {
      kdfparams.n = options.n || 262144;
      kdfparams.r = options.r || 8;
      kdfparams.p = options.p || 1;

      let saltUse = [];

      for (let i=0; i<salt.length; i++) {
        saltUse.push(salt[i]);
      }

      scrypt(password, salt, {N: kdfparams.n, r: kdfparams.r, p: kdfparams.p, dklen: kdfparams.dklen, encoding: 'binary'}, cb);
    } else {
      throw new Error('Unsupported key derivation function.');
    }
  } catch (err) {
    callback(err, null);
  }
};

module.exports = exports = wallet;
