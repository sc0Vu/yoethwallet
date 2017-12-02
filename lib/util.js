const util = {};

util.bufferToArray = function (buffer) {
  const length = buffer.length;
  let data = [];

  for (let i=0; i<length; i++) {
    data.push(buffer[i]);
  }
  return data;
};

module.exports = exports = util;