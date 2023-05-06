const node_openssl = require('../index.js');
var fs = require('fs');
var tmp = require('tmp');

var options = {
	binpath: 'C:/Program Files/OpenSSL-Win64/bin/openssl.exe'
}

var openssl = new node_openssl(options);

var rsakeyoptions = {
	rsa_keygen_bits: 2048,
	//rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}

var csroptions = {
	hash: 'sha512',
	string_mask: 'default',
	startdate: new Date('1984-02-04 00:00:00'),
	enddate: new Date('2143-06-04 04:16:23'),
	//days: 600,
	requestAttributes: {
		challengePassword: 'CHALLENGEPASSPHRASE',
		unstructuredName: 'Optional Company Name'
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
	},
	extensions: {
		customOIDs: [{
			OID: '1.3.6.1.4.1.11129.2.4.3',
			value: 'critical,ASN1:NULL'
		}],
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
				'1.3.6.1.4.1.311.10.3.1',
				'1.3.6.1.4.1.311.10.3.3',
				'1.3.6.1.4.1.311.10.3.4',
				'2.16.840.1.113730.4.1',
				'1.3.6.1.4.1.311.20.2.2',
				'1.2.3.4'
			]	
		},
		SANs: {
			DNS: [
				'google.com',
				'www.google.com'
			]
		}
	}
}

openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
	if(err) {
		console.log(err);
	} else {
		openssl.generateCSR(csroptions, key, false, function(err, csr, cmd) {
			if(err) {
				console.log(err);
				//console.log(cmd.files.config);
			} else {
				console.log(csr);
				console.log(cmd.files.config);
				openssl.selfSignCSR(csr, csroptions, key, false, function(err, crt, cmd) {
					if(err) {
						console.log(err);
						console.log(cmd.files.config);
					} else {
						console.log(crt);
						console.log(cmd.files.config);
						openssl.getCertInfo(crt, function(err, certinfo, cmd) {
							if(err) {
								console.log(err);
							} else {
								console.log(certinfo.extensions);
							}
						})
					}
				});
			}
		});
	}
});