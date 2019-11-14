const node_openssl = require('../index.js');
var fs = require('fs');

var options = {
	//binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
	binpath: 'C:/Program Files/OpenSSL-Win64/bin/openssl.exe'
}

var openssl = new node_openssl(options);

fs.readFile('./twitter2.crt', function(err, contents) {
	openssl.getOpenSSLCertInfo(contents, function(err, out, cmd) {
		if(err) {
			console.log(err);
		} else {
			console.log(out);
		}
	});
});