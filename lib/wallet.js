const ethUtil = require('ethereumjs-util');
const crypto = require('crypto');
const scrypt = require('scrypt-async');
const uuid = require('uuid');
const bip39 = require('bip39');
const wordlist = bip39.wordlists.EN;
const util = require('./util');
const keystore = require('./keystore');
const wallet = {};

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
      const salt = util.bufferToArray(saltBuffer);

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

module.exports = exports = wallet;
