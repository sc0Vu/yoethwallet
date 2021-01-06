const crypto = require('crypto');
let scrypt = crypto.scrypt;
const isWASM = scrypt === undefined;
const scryptWASM = require('wasm-scrypt/dist/node-bundle.js');

module.exports = async function (pwd, salt, dklen, opts, cb) {
  if (isWASM) {
    if (scrypt === undefined) {
      scrypt = await scryptWASM();
    }
    const kdf = scrypt.kdf(pwd, 'utf8', salt.toString('hex'), 'hex', dklen, opts);
    if (kdf.length > 0) {
      cb(null, kdf);
    } else {
      cb(new Error('wrong parameters to scrypt'), null);
    }
  } else {
    scrypt(pwd, salt, dklen, opts, cb);
  }
}