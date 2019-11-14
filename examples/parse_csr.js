const node_openssl = require('../index.js');
var fs = require('fs');

var options = {
	//binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
	binpath: 'C:/Program Files/OpenSSL-Win64/bin/openssl.exe'
}

var openssl = new node_openssl(options);

var rsakeyoptions = {
	encryption: {
		password: 'test',
		cipher: 'des3'
	},
	rsa_keygen_bits: 2048,
	//rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}

fs.readFile('./example.csr', function(err, contents) {
	openssl.getCSRInfo(contents, function(err, attrs, cmd) {
		if(err) {
			console.log(err);
		} else {
			console.log(attrs);
			openssl.generateConfig(attrs, false, false, function(err, config) {
				//console.log(config);
				openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
					//console.log(cmd);
					//console.log(key);
					openssl.generateCSR(attrs, key, 'test', function(err, csr, cmd) {
						if(err) {
							console.log(err);
						} else {
							//console.log(cmd.command);
							//console.log(csr);
							//console.log(cmd.files.config);
							openssl.selfSignCSR(csr, attrs, key, 'test', function(err, crt, cmd) {
								if(err) {
										console.log(err);
										console.log(cmd.files.config);
								} else {
										//console.log(cmd.command);
										console.log(crt);
										//console.log(cmd.files.config);
								}
							});
						}
							
					});
				});
			});
			//console.log(openssl.getDistinguishedName(attrs.subject));
		}
	});
});