const util = {};

util.bufferToArray = function (buffer) {
  const length = buffer.length;
  const data = [];

  for (let i = 0; i < length; i++) {
    data.push(buffer[i]);
  }
  return data;
};

util.callable = function (src) {
  const srcType = typeof src;
  return srcType === 'function';
};

module.exports = util;
