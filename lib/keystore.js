const ethUtil = require('ethereumjs-util');
const crypto = require('crypto');
const scrypt = crypto.scrypt;
const uuid = require('uuid');
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
  get: function () {
    return this._privateKey;
  },
});

Object.defineProperty(keystore.prototype, 'publicKey', {
  get: function () {
    return this._publicKey;
  },
});

Object.defineProperty(keystore.prototype, 'hdKey', {
  get: function () {
    return this._hdKey;
  },
  set: function (hdKey) {
    this._hdKey = hdKey;
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
    const encCB = function (err, derivedKey) {
      if (err) {
        callback(err, null);
        return
      }
      derivedKey = derivedKey;

      let cipher = crypto.createCipheriv(cipherAlgorithm, derivedKey.slice(0, 16), iv);

      if (!cipher) {
        callback(new Error('Unsupported cipher algorithm.'), null);
        return;
      }

      const ciphertext = Buffer.concat([ cipher.update(this._privateKey), cipher.final() ]);
      const mac = ethUtil.sha3(Buffer.concat([ derivedKey.slice(16, 32), Buffer.from(ciphertext, 'hex') ]));

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
      crypto.pbkdf2(Buffer.from(password), salt, kdfparams.c, kdfparams.dklen, 'sha256', function (err, derivedKey) {
        if (err) {
          callback(err, null);
          return;
        }
        encCB(null, derivedKey);
      });
    } else if (kdf === 'scrypt') {
      kdfparams.n = options.n || 262144;
      kdfparams.r = options.r || 8;
      kdfparams.p = options.p || 1;
      // use quite more memory, should found a better formula (see: https://github.com/nodejs/node/issues/21524)
      const maxmem = 128 * kdfparams.n * kdfparams.r * kdfparams.dklen;

      scrypt(password, salt, kdfparams.dklen, { N: kdfparams.n, r: kdfparams.r, p: kdfparams.p, maxmem: maxmem }, encCB);
    } else {
      throw new Error('Unsupported key derivation function.');
    }
  } catch (err) {
    callback(err, null);
  }
};

module.exports = exports = keystore;