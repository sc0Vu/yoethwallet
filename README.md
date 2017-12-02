# yoethwallet
[![Build Status](https://travis-ci.org/sc0Vu/yoethwallet.svg?branch=master)](https://travis-ci.org/sc0Vu/yoethwallet)
[![codecov](https://codecov.io/gh/sc0Vu/yoethwallet/branch/master/graph/badge.svg)](https://codecov.io/gh/sc0Vu/yoethwallet)

Another ethereum wallet.

# Install

```
npm install yoethwallet --save
```

# Usage

Create wallet from seed

```
const yoethwallet = require('yoethwallet')
const wallet = yoethwallet.wallet.generate(seed, hdPath, (err, instance) => {
  // 
});

// get address buffer
wallet.getAddress()
```

Create wallet from v3 json

```
const wallet = yoethwallet.wallet.fromV3String('valid v3 json get from wallet.toJson('password')', 'password')

// get address buffer
wallet.getAddress()
```

# API

### Wallet

`generate(randomSeed, hdPath, callback)`

Generate wallet.

`validateSeed(seed)`

Validate seed.

`getV3Filename()`

Get v3 filename.

`toV3String(password, options, callback)`

options
```
{
  salt: '...',
  iv: '...',
  dklen: '...',
  kdf: '...',
  cipher: '...',
  // if kdf is pbkdf
  c: '',
  // if kdf is scrypt
  n: '',
  r: '',
  p: '',
}

Remember the right dklen, cipher and iv size.
```

Export wallet to json.

`getPrivateKey()`

Get private key buffer.

`getHexPrivateKey()`

Get private key hex string.

`getPublicKey()`

Get public key buffer.

`getHexPublicKey()`

Get public key hex string.

`getAddress()`

Get address buffer.

`getHexAddress(withPrefix)`

Get address hex string with 0x prefix or not.

`fromV3String(json, password, callback)`
Import wallet from v3 json string.

`fromPrivateKey(privateKey, callback)`
Import wallet from private key.

`fromHdKey(hdKey, callback)`
Import wallet from hdKey.

### Tx

`valueTx(txParams)`

Create value transaction.

```
txParams: {
  to: '0x0000000000000000000000000000000000000000',
  gas: 21000,
  gasPrice: 1,
  gasLimit: 21000
}
```

`contractTx(data, txParams)`

Create contract transaction.

```
data: contract data
txParams: {
  to: '0x0000000000000000000000000000000000000000',
  gas: 210000,
  gasPrice: 1,
  gasLimit: 210000
}
```

# License

MIT
