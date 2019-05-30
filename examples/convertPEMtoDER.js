const node_openssl = require('../index.js');
var fs = require('fs');

var options = {
	binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
}

var openssl = new node_openssl(options);

fs.readFile('./ca.crt', function(err, contents) {
	openssl.convertPEMtoDER(contents, function(err, data) {
		if(err) {
			console.log(err);
		} else {
			console.log(data.toString());
		}
	});
});