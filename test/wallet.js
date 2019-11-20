const tape = require('tape');
const yoethwallet = require('../index');

let wallet = {};
let walletJson = '';
let pkWalletJson = '';
let address = '';
let privateKey = '';

tape('before yoethwallet wallet test', (t) => {
  yoethwallet.wallet.generate('', '', (err, instance) => {
    if (err) {
      t.equal(err, null);
      return;
    }
    wallet = instance;
    t.end();
  });
});

tape('yoethwallet wallet test', (t) => {
  t.test('validate seed', (st) => {
    st.equal(yoethwallet.wallet.validSeed('notice duck nut oval cupboard spend border wagon chest forest crane video'), true);
    st.equal(yoethwallet.wallet.validSeed('hello world'), false);
    st.end();
  });

  t.test('validate hdPath', (st) => {
    st.equal(yoethwallet.wallet.validHdPath('m/44\'/60\'/0\'0'), true);
    st.equal(yoethwallet.wallet.validHdPath(''), false);
    st.end();
  });

  t.test('sholud get V3 file name', (st) => {
    st.equal(/^UTC\-\-(?:[a-zA-Z0-9\-\.]+)\-\-(?:[a-fA-F0-9]+)$/.test(wallet.getV3Filename()), true);
    st.end();
  });

  t.test('sholud get V3 json with default scrypt and aes-128-ctr', (st) => {
    wallet.toV3String('123456', {}, (err, v3String) => {
      if (err) {
        st.equal(err, null);
      }
      walletJson = v3String;

      const v3 = JSON.parse(walletJson);

      st.equal(v3.version, 3);
      st.equal(v3.crypto.cipher, 'aes-128-ctr');
      st.equal(v3.crypto.kdf, 'scrypt');
      st.end();
    });
  });

  t.test('sholud get V3 json with pbkdf2 and aes128', (st) => {
    wallet.toV3String('123456', { kdf: 'pbkdf2', cipher: 'aes128' }, (err, v3String) => {
      const v3 = JSON.parse(v3String);

      pkWalletJson = v3String;

      st.equal(v3.version, 3);
      st.equal(v3.crypto.cipher, 'aes128');
      st.equal(v3.crypto.kdf, 'pbkdf2');
      st.end();
    });
  });

  t.test('should get hex private key', (st) => {
    st.equal(/^[a-fA-F0-9]+$/.test(wallet.getHexPrivateKey()), true);
    st.end();
  });

  t.test('should get hex public key', (st) => {
    st.equal(/^[a-fA-F0-9]+$/.test(wallet.getHexPublicKey()), true);
    st.end();
  });

  t.test('should get private key buffer', (st) => {
    privateKey = wallet.getPrivateKey();

    st.equal(privateKey.toString('hex'), wallet.getHexPrivateKey());
    st.equal(wallet.privateKey.toString('hex'), wallet.getHexPrivateKey());
    st.end();
  });

  t.test('should get public key buffer', (st) => {
    st.equal(wallet.getPublicKey().toString('hex'), wallet.getHexPublicKey());
    st.equal(wallet.publicKey.toString('hex'), wallet.getHexPublicKey());
    st.end();
  });

  t.test('should get hex address with prefix 0x', (st) => {
    address = wallet.getHexAddress(true);

    st.equal(/^0x[a-fA-F0-9]{40}$/.test(address), true);
    st.end();
  });

  t.test('should generate from v3 json string with scrypt', (st) => {
    yoethwallet.wallet.fromV3String(walletJson, '123456', (err, v3Wallet) => {
      if (err) {
        st.equal(err, null);
      }
      st.equal(v3Wallet.getHexAddress(true), address);
      st.end();
    });
  });

  t.test('should generate from v3 json string with pkdf2', (st) => {
    yoethwallet.wallet.fromV3String(pkWalletJson, '123456', (err, v3Wallet) => {
      if (err) {
        st.equal(err, null);
      }
      st.equal(v3Wallet.getHexAddress(true), address);
      st.end();
    });
  });

  t.test('should generate from private key', (st) => {
    yoethwallet.wallet.fromPrivateKey(privateKey, (err, instance) => {
      if (err) {
        st.equal(err, null);
      }
      st.equal(instance.getHexAddress(true), address);
      st.end();
    });
  });

  t.test('should generate from hdKey', (st) => {
    yoethwallet.wallet.fromHdKey(wallet.hdKey, (err, instance) => {
      if (err) {
        st.equal(err, null);
      }
      st.equal(instance.getHexAddress(true), address);
      st.end();
    });
  });

  t.end();
});
