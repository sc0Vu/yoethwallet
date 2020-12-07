const ethUtil = require('ethereumjs-util');
const crypto = require('crypto');
const scrypt = crypto.scrypt;
const bip39 = require('bip39');
const wordlist = bip39.wordlists.EN;
const Keystore = require('./keystore');
const HDKey = require('hdkey');
const wallet = {};
const defaultHDPath = 'm/44\'/60\'/0\'0';

wallet.validSeed = function (seed) {
  if (typeof seed !== 'string') {
    return false;
  }
  return bip39.validateMnemonic(seed, wordlist);
};

wallet.validHdPath = function (hdPath) {
  if (hdPath !== '' && hdPath !== undefined) {
    return true;
  }
  return false;
};

wallet.generate = function (mnemonic, hdPath, callback) {
  try {
    let randomSeed = '';
    if (!mnemonic || !this.validSeed(mnemonic)) {
      mnemonic = bip39.generateMnemonic();
    }

    randomSeed = bip39.mnemonicToSeedHex(mnemonic);
    hdPath = (this.validHdPath(hdPath)) ? hdPath : defaultHDPath;

    const hdKey = HDKey.fromMasterSeed(randomSeed);
    const _hdKey = hdKey.derive(hdPath);
    const cb = function (err, keystore) {
      if (err == null) {
        keystore.mnemonic = mnemonic;
      }
      callback(err, keystore)
    }

    this.fromHdKey(_hdKey, cb);
  } catch (err) {
    callback(err, null);
  }
};

wallet.fromPrivateKey = function (privateKey, callback) {
  try {
    callback(null, new Keystore(privateKey));
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

    const encCB = function (err, derivedKey) {
      if (err) {
        callback(err, null);
        return
      }
      derivedKey = derivedKey;

      const ciphertext = Buffer.from(v3.crypto.ciphertext, 'hex');
      const mac = ethUtil.sha3(Buffer.concat([ derivedKey.slice(16, 32), ciphertext ]));

      if (mac.toString('hex') !== v3.crypto.mac) {
        callback(new Error('Key derivation failed.'), null);
      }

      let decipher = crypto.createDecipheriv(v3.crypto.cipher, derivedKey.slice(0, 16), Buffer.from(v3.crypto.cipherparams.iv, 'hex'));
      const seed = Buffer.concat([ decipher.update(ciphertext), decipher.final() ]);

      callback(null, new Keystore(seed));
    };

    if (v3.crypto.kdf === 'pbkdf2') {
      const kdfparams = v3.crypto.kdfparams;

      if (kdfparams.prf !== 'hmac-sha256') {
        throw new Error('PBKDF2 prf must be hmac-sha256.');
      }

      crypto.pbkdf2(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256', function (err, derivedKey) {
        if (err) {
          callback(err, null);
          return;
        }
        encCB(null, derivedKey);
      });
    } else if (v3.crypto.kdf === 'scrypt') {
      const kdfparams = v3.crypto.kdfparams;
      const saltBuffer = Buffer.from(kdfparams.salt, 'hex');
      // use quite more memory, should found a better formula (see: https://github.com/nodejs/node/issues/21524)
      const maxmem = 128 * kdfparams.n * kdfparams.r * kdfparams.dklen;

      scrypt(password, saltBuffer, kdfparams.dklen, { N: kdfparams.n, r: kdfparams.r, p: kdfparams.p, maxmem: maxmem }, encCB);
    } else {
      throw new Error('Unsupported key derivation scheme.');
    }
  } catch (err) {
    callback(err, null);
  }
};

wallet.fromHdKey = function (hdKey, callback) {
  try {
    if (!hdKey._privateKey) {
      throw new Error('Something wrong in hdkey.');
    }
    const keystore = new Keystore(hdKey._privateKey);
    
    keystore.hdKey = hdKey;

    callback(null, keystore);
  } catch (err) {
    callback(err, null);
  }
};

module.exports = exports = wallet;
