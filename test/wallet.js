const tape = require('tape');
const yoethwallet = require('../index');
// const crypto = require('crypto');

tape('yoethwallet wallet test', (t) => {
  const wallet = yoethwallet.wallet;
  let walletJson = '';
  let address = '';
  let privateKey = '';

  wallet.generate();

  t.test('validate seed', (st) => {
    st.equal(wallet.validateSeed('notice duck nut oval cupboard spend border wagon chest forest crane video'), true);
    st.equal(wallet.validateSeed('hello world'), false);
    st.end();
  });

  t.test('sholud get V3 file name', (st) => {
    st.equal(/^UTC\-\-(?:[a-zA-Z0-9\-\.]+)\-\-(?:[a-fA-F0-9]+)$/.test(wallet.getFilename()), true);
    st.end();
  });

  t.test('sholud get V3 json with default scrypt and aes-128-ctr', (st) => {
    walletJson = wallet.toJson('123456');

    const v3 = JSON.parse(walletJson);

    st.equal(v3.version, 3);
    st.equal(v3.crypto.cipher, 'aes-128-ctr');
    st.equal(v3.crypto.kdf, 'scrypt');
    st.end();
  });

  t.test('sholud get V3 json with pbkdf2 and aes128', (st) => {
    const v3 = JSON.parse(wallet.toJson('123456', {kdf: 'pbkdf2', cipher: 'aes128'}));

    st.equal(v3.version, 3);
    st.equal(v3.crypto.cipher, 'aes128');
    st.equal(v3.crypto.kdf, 'pbkdf2');
    st.end();
  });

  t.test('should get private key', (st) => {
    st.equal(/^[a-fA-F0-9]+$/.test(wallet.getPrivateKey()), true);
    st.end();
  });

  t.test('should get public key', (st) => {
    st.equal(/^[a-fA-F0-9]+$/.test(wallet.getPublicKey()), true);
    st.end();
  });

  t.test('should get private key buffer', (st) => {
    privateKey = wallet.getPrivateKeyBuffer();

    st.equal(privateKey.toString('hex'), wallet.getPrivateKey());
    st.end();
  });

  t.test('should get public key buffer', (st) => {
    st.equal(wallet.getPublicKeyBuffer().toString('hex'), wallet.getPublicKey());
    st.end();
  });

  t.test('should get address', (st) => {
    address = wallet.getAddress();

    st.equal(/^0x[a-fA-F0-9]{40}$/.test(address), true);
    st.end();
  });

  t.test('should generate from v3 json string', (st) => {
    const v3Wallet = yoethwallet.wallet;

    v3Wallet.fromJson(walletJson, '123456');

    st.equal(v3Wallet.getAddress(), address);
    st.end();
  });

  t.test('should generate from private key', (st) => {
    const pkWallet = wallet.fromPrivateKey(privateKey);

    st.equal(pkWallet.getAddress(), address);
    st.end();
  });

  t.end();
});
