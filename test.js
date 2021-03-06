const fs = require('fs-extra');
const path = require('path');

fs.readdir(path.join(__dirname, 'test'))
  .then((files) => {
    function runTest(file) {
      try {
        require(path.join(__dirname, 'test', file));
      } catch (e) {
        console.log(`Run test ${file} error: ${e.message}`);
      }
    }

    files = files.filter(file => /^([a-zA-Z0-9]+)\.js$/.test(file.trim()));
    files.forEach((file) => {
      runTest(file);
    });
  })
  .catch((err) => {
    console.log(`Read directory error: ${err.message}`);
  });
