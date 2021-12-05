const node_openssl = require('../index.js');
var fs = require('fs');

var options = {
	//binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
	binpath: 'C:/Program Files/OpenSSL-Win64/bin/openssl.exe'
}

var openssl = new node_openssl({});

fs.readFile('./cert.csr', function(err, contents) {
	//console.log(contents)
	openssl.getCSRInfo(contents.toString(), function(err, attrs, cmd) {
		if(err) {
			console.log(err);
		} else {
			console.log(JSON.stringify(attrs, null, 2));
		}
	});
});