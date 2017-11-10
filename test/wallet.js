const tape = require('tape');
const yoethwallet = require('../index');
// const crypto = require('crypto');

tape('yoethwallet wallet test', (t) => {
  const wallet = yoethwallet.wallet;
  const walletJson = '{"version":3,"id":"14c3ce7b-137d-4e7f-b7ae-addcc463b855","address":"c4a7d55f6bc573cfb72dd04f8b3e84ca6789a2ea","crypto":{"ciphertext":"3aa0bb0578a9c1b0af5f30e05d73c2536bba515e3e488c1fe34c1334a339c3ae","cipherparams":{"iv":"eebcd53b12a0e7975ec101ad5e7d95ab"},"cipher":"aes-128-ctr","kdf":"scrypt","kdfparams":{"dklen":32,"salt":"262a812d44d7bf27d99f58e134e6b97a8194e818a3ae73cdb12eb7e74b6ed264","n":262144,"r":8,"p":1},"mac":"67902a90cc0e5b5a8eefea810a37c5347d8009575ef89c5a15776f75150d558f"}}';

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
    const v3 = JSON.parse(wallet.toJson('123456'));

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
    st.equal(wallet.getPrivateKeyBuffer().toString('hex'), wallet.getPrivateKey());
    st.end();
  });

  t.test('should get public key buffer', (st) => {
    st.equal(wallet.getPublicKeyBuffer().toString('hex'), wallet.getPublicKey());
    st.end();
  });

  t.test('should get address', (st) => {
    st.equal(/^0x[a-fA-F0-9]{40}$/.test(wallet.getAddress()), true);
    st.end();
  });

  t.test('should generate from v3 json string', (st) => {
    const v3Wallet = yoethwallet.wallet;

    v3Wallet.fromJson(walletJson, '123456');
    st.equal(v3Wallet.getAddress(), '0xc4a7d55f6bc573cfb72dd04f8b3e84ca6789a2ea');
    st.end();
  });

  t.end();
});
