const node_openssl = require('../index.js');
var fs = require('fs');

var options = {
	//binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
	binpath: 'C:/Program Files/OpenSSL-Win64/bin/openssl.exe'
}

var openssl = new node_openssl(options);

fs.readFile('./ca.crt', function(err, contents) {
	//console.log(contents.toString());
	openssl.getCertInfo(contents.toString(), function(err, certinfo) {
		console.log(openssl.getDistinguishedName(certinfo.subject));
	});
});