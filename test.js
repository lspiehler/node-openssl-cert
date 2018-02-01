const node_openssl = require('./index.js');

var openssl = new node_openssl();

var rsakeyoptions = {
	encryption: {
		password: 'test',
		cipher: 'des3'
	},
	/*rsa_keygen_bits: 2048,
	//rsa_keygen_primes: 2, //causes an error, maybe openssl version?
	//rsa_keygen_pubexp: 65537,
	format: 'PKCS8'*/
}

var csroptions = {
	hash: 'sha256',
	subject: {
		countryName: 'US',
		stateOrProvinceName: 'Louisiana',
		localityName: 'Slidell',
		postalCode: '70458',
		streetAddress: '1001 Gause Blvd.',
		organizationName: 'SMH',
		organizationalUnitName: 'IT',
		commonName: [
			'kernelmanic.com',
			'www.kernelmanic.com'
		],
		emailAddress: 'lyas.spiehler@slidellmemorial.org'
	},
	extensions: {
		basicConstraints: {
			critical: true,
			CA: true,
			pathlen: 1
		},
		keyUsage: [
			'digitalSignature',
			'keyEncipherment'
		],
		extendedKeyUsage: [
			'serverAuth',
			'clientAuth'
		],
		SANs: {
			DNS: [
				'kernelmanic.com',
				'www.kernelmanic.com'
			]
		}
	}
}

openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key) {
	console.log(key);
	openssl.generateCSR(csroptions, key, function(err, csr) {
		//console.log(csr);
		if(err) {
			console.log(err);
		} else {	
			console.log(csr.data);
		}
			
	});
});


//ca only keyusage keyCertSign, cRLSign
//all explanations https://superuser.com/questions/738612/openssl-ca-keyusage-extension