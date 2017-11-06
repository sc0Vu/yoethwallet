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
const wallet = yoethwallet.wallet.generate()

// get address
wallet.getAddress()
```

Create wallet from v3 json

```
const wallet = yoethwallet.wallet.fromJson('valid v3 json get from wallet.toJson('password')', 'password')

// get address
wallet.getAddress()
```

# API

### Wallet

`generate(randomSeed, hdPath)`

Generate wallet.

`validateSeed(seed)`

Validate seed.

`getFilename()`

Get v3 filename.

`toJson(password)`

Export wallet to json.

`getPrivateKey()`

Get private key hex string.

`getPublicKey()`

Get public key hex string.

`getAddress()`

Get address hex string with 0x prefix.

`fromJson(json, password)`
Import wallet from v3 json string.

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
