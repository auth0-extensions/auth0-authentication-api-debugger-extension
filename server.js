const nconf = require('nconf');
const path = require('path');

nconf
    .argv()
    .env()
    .file(path.join(__dirname, './config.json'));


var port = process.env.PORT || 3000;

const app = require('./index.js')(function(key) { return nconf.get(key);}, null); 

app.listen(port, function () {
    console.log('Server started on port', port);
})
