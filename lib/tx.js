const ethTx = require('ethereumjs-tx');

const tx = {};

tx.valueTx = function (txParams) {
  const tx = new ethTx(txParams);

  return tx;
};

tx.contractTx = function (data, txParams) {
  txParams.data = data;

  const tx = new ethTx(txParams);

  return tx;
};

module.exports = tx;
