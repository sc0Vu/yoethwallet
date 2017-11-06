var fs = require('fs-extra')
var path = require('path')

fs.readdir(path.join(__dirname, 'test'))
  .then(function (files) {
    function runTest(file) {
      try {
        require(path.join(__dirname, 'test', file))
      } catch(e) {
        console.log(`Run test ${file} error: ${e.message}`)
      }
    }

    files = files.filter(function (file) {
      return /^([a-zA-Z0-9]+)\.js$/.test(file.trim())
    })
    files.forEach(function (file) {
      runTest(file)
    })
  })
  .catch((err) => {
    console.log(`Read directory error: ${err.message}`)
  })