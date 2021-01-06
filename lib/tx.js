const ethTx = require('ethereumjs-tx');
const tx = {}

tx.valueTx = function (txParams) {
  let tx = new ethTx(txParams);

  return tx;
}

tx.contractTx = function (data, txParams) {
  txParams.data = data;

  let tx = new ethTx(txParams);

  return tx;
}

module.exports = tx;