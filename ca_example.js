const node_openssl = require('./index.js');
var fs = require('fs');
var openssl = new node_openssl();

var rsakeyoptions = {
	encryption: {
		password: 'test',
		cipher: 'des3'
	},
	rsa_keygen_bits: 2048,
	//rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}

var csroptions = {
	hash: 'sha512',
	days: 240,
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
	},
	extensions: {
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
				'clientAuth'
			]	
		},
		SANs: {
			DNS: [
				'certificatetools.com',
				'www.certificatetools.com'
			]
		}
	}
}

var cacsroptions = {
	hash: 'sha512',
	days: 240,
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
			'Test CA'
		]
	},
	extensions: {
		basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 1
		},
		keyUsage: {
			critical: true,
			usages: [
				'digitalSignature',
				'keyEncipherment',
				'keyCertSign'
			]
		},
		extendedKeyUsage: {
			critical: true,
			usages: [
				'serverAuth',
				'clientAuth'
			]	
		}
	}
}

openssl.generateRSAPrivateKey(rsakeyoptions, function(err, cakey, cmd) {
	openssl.generateCSR(cacsroptions, cakey, 'test', function(err, csr, cmd) {
		if(err) {
			console.log(err);
		} else {
			openssl.selfSignCSR(csr, cacsroptions, cakey, 'test', function(err, cacrt, cmd) {
				if(err) {
					console.log(err);
				} else {
//					console.log(crt);
					openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
						openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
							//console.log(cakey);
							//console.log(crt);
							openssl.CASignCSR(csr, cacsroptions, cacrt ,cakey, 'test', function(err, crt, cmd) {
								console.log(cmd);
								if(err) console.log(err);
								console.log(crt);
								console.log(cmd);
								openssl.createPKCS12(crt, key, 'test', '12345', cacrt, function(err, pfx, command) {
									if(err) {
										//console.log(err);
										//console.log(command);
									} else {
										//console.log(pfx);
										//console.log(command);
									}
									
								});
							});
						});
					});
				}
			});
		}
			
	});
});