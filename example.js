const node_openssl = require('./index.js');
var fs = require('fs');

var options = {
	binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
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

var ecckeyoptions = {
	encryption: {
		password: 'test',
		cipher: 'des3'
	},
	curve: 'prime256v1',
	//rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}

var csroptions = {
	hash: 'sha512',
	days: 240,
	extensions: {
		tlsfeature: ['status_request'],
		basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 1
		},
		keyUsage: {
			critical: true,
			usages: [
				'digitalSignature',
				'keyEncipherment'
			]
		},
		extendedKeyUsage: {
			critical: true,
			usages: [
				'serverAuth',
				'clientAuth',
				'ipsecIKE',
				'ipsecUser',
				'ipsecTunnel',
				'ipsecEndSystem'
			]	
		},
		SANs: {
			DNS: [
				'certificatetools.com',
				'www.certificatetools.com'
			]
		}
	},
	subject: {
		countryName: 'US',
		stateOrProvinceName: 'Louisiana',
		localityName: 'Slidell',
		postalCode: '70458',
		streetAddress: '1001 Gause Blvd.',
		organizationName: 'SMH',
		organizationalUnitName: [
				'IT'
		],
		commonName: [
				'certificatetools.com',
				'www.certificatetools.com'
		],
		emailAddress: 'lyas.spiehler@slidellmemorial.org'
	}

}

var csroptions = {
	hash: 'sha256',
	subject: {
		countryName: 'US'
	}

}

var netcertoptions = {
	hostname: 'barracuda1.smhplus.org',
	port: 25,
	starttls: true,
	protocol: 'smtp'
}

var netcertoptions = {
	hostname: '47.91.46.102',
	port: 443,
	starttls: false,
	//protocol: 'https'
}

openssl.generateConfig(csroptions, true, false, function(err, config) {
	console.log(config);
});

/*var netcertoptions = {
	hostname: 'barracuda1.smhplus.org',
	port: 25,
	starttls: true,
	protocol: 'smtp'
})*/

/*openssl.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
	if(err) console.log(err);
	console.log(cmd);
	console.log(cert);
});*/

/*fs.readFile('./googletest.crt', function(err, contents) {
	openssl.convertCertToCSR(contents, function(err,csroptions,cmd) {
		console.log(csroptions);
	});
});*/

/*openssl.generateECCPrivateKey(ecckeyoptions, function(err, key, cmd) {
	console.log(cmd);
	openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
			if(err) {
					console.log(err);
					console.log(cmd.files.config);
			} else {
					console.log(cmd);
					//console.log(csr);
					//console.log(cmd.files.config);
					csroptions.days = 240;
					openssl.selfSignCSR(csr, csroptions, key, 'test', function(err, crt, cmd) {
							if(err) {
									console.log(err);
									console.log(cmd.files.config);
							} else {
									console.log(cmd.command);
									console.log(crt);
									console.log(cmd.files.config);
							}
					});
			}

	});
});*/

/*openssl.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
	console.log(cert);
	//console.log(cmd);
	if(err) console.log(err);
	//console.log(cert);
	openssl.convertCertToCSR(cert[0], function(err,csroptions,cmd) {
		console.log(csroptions);
		//console.log(cmd);
		return;
		openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
			console.log(cmd);
			openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
				if(err) {
					console.log(err);
					console.log(cmd.files.config);
				} else {
					console.log(cmd);
					//console.log(csr);
					//console.log(cmd.files.config);
					csroptions.days = 240;
					openssl.selfSignCSR(csr, csroptions, key, 'test', function(err, crt, cmd) {
						if(err) {
							console.log(err);
							console.log(cmd.files.config);
						} else {
							console.log(cmd.command);
							console.log(crt);
							console.log(cmd.files.config);
						}
					});
				}
					
			});
		});
	});
});*/

/*openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
	console.log(cmd);
	console.log(key);
	openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
		if(err) {
			console.log(err);
		} else {
			console.log(cmd.command);
			console.log(csr);
			console.log(cmd.files.config);
		}
			
	});
});*/

/*fs.readFile('./test/ecc.key', function(err, contents) {
    openssl.importECCPrivateKey(contents, 'test test', function(err, key, cmd) {
	//console.log(cmd);
		if(err) {
			console.log(err);
		} else {	
			console.log(key);
		}
	//return;
		openssl.generateCSR(csroptions, key, 'test test', function(err, csr, cmd) {
			if(err) {
				console.log(err);
			} else {	
				console.log(csr);
			}
				
		});
	});
});*/

/*openssl.getCertFromURL('yahoo.com',function(err, cert) {
	if(err) console.log(err);
	console.log(cert.pemEncoded);
	openssl.convertCertToCSR(cert.pemEncoded, function(err,csroptions,cmd) {
		//console.log(csroptions.subject);
		openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
			openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
				if(err) {
					console.log(err);
					console.log(cmd.files.config);
				} else {
					//console.log(cmd.command);
					console.log(csr);
					//console.log(cmd.files.config);
				}
					
			});
		});
	});
});*/

/*openssl.getCertFromURL('yahoo.com',function(err, cert) {
	openssl.convertCertToCSR(cert.pemEncoded, function(err,csroptions,cmd) {
		openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
			openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
				console.log(csr);
			});
		});
	});
});*/

/*fs.readFile('./test/test.crt', function(err, contents) {
	//console.log(contents.toString());
	openssl.convertCertToCSR(contents.toString(), function(err,csroptions,cmd) {
		console.log(csroptions);
		openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
			openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
				if(err) {
					console.log(err);
				} else {
					//console.log(cmd.command);
					console.log(csr);
					//console.log(cmd.files.config);
				}
					
			});
		});
	});
});*/


//ca only keyusage keyCertSign, cRLSign
//all explanations https://superuser.com/questions/738612/openssl-ca-keyusage-extension
