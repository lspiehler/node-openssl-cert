const node_openssl = require('./index.js');
var fs = require('fs');
var openssl = new node_openssl();

var rsakeyoptions = {
	encryption: {
		password: 'test',
		cipher: 'des3'
	},
	rsa_keygen_bits: 2048,
	rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}

var csroptions = {
	hash: 'sha512',
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
		/*basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 1
		},
		keyUsage: {
			//critical: false,
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
		},*/
		SANs: {
			DNS: [
				'certificatetools.com',
				'www.certificatetools.com'
			]
		}
	}
}

var netcertoptions = {
	hostname: 'barracuda1.smhplus.org',
	port: 25,
	starttls: true,
	protocol: 'smtp'
}

var netcertoptions = {
	hostname: 'kernelmanic.com',
	port: 443,
	starttls: false,
	protocol: 'https'
}

openssl.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
	//console.log(cert);
	//console.log(cmd);
	if(err) console.log(err);
	//console.log(cert);
	openssl.convertCertToCSR(cert, function(err,csroptions,cmd) {
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
});

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

/*fs.readFile('./test/rsa.key', function(err, contents) {
    openssl.importRSAPrivateKey(contents, 'test', function(err, key, cmd) {
		openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
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