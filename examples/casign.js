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
	startdate: new Date('1984-02-04 00:00:00'),
	enddate: new Date('2143-06-04 04:16:23'),
	//days: 600,
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

//var path = 'C:/Users/Lyas/Desktop/nodetest/cadir';

fs.readFile('./ca.key', function(err, cakey) {
	fs.readFile('./ca.crt', function(err, cacrt) {
		openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
			openssl.generateCSR(csroptions, key, false, function(err, csr, cmd) {
				//console.log(cakey);
				//console.log(crt);
				tmp.dir({unsafeCleanup: true}, function _tempDirCreated(err, path, cleanupCallback) {
					fs.writeFile(path + '/ca.key', cakey, function(err) {
						if(err) {
							cleanupCallback()
						} else {
							fs.writeFile(path + '/ca.crt', cacrt, function(err) {
								if(err) {
									cleanupCallback()
								} else {
									fs.writeFile(path + '/index.txt', '', function(err) {
										if(err) {
											cleanupCallback()
										} else {
											fs.mkdir(path + '/certs', function(err) {
												if(err) {
													cleanupCallback()
												} else {
													//console.log(path);
													let osslpath;
													if(path.indexOf('\\') >= 0) {
														osslpath = path.split('\\').join('\\\\')
													} else {
														osslpath = path;
													}
													console.log(osslpath);
													openssl.CASignCSR(csr, csroptions, osslpath, false, false, false, function(err, crt, cmd) {
														cleanupCallback()
														if(err) {
															console.log(err);
														} else {
															console.log(crt);
															console.log(cmd);
														}
													});
												}
											});
										}
									});
								}
							});
						}
					});
				});
			});
		});
	});
});

/*fs.readFile('./ca.key', function(err, cakey) {
	fs.readFile('./ca.crt', function(err, cacrt) {
		openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
			openssl.generateCSR(csroptions, key, false, function(err, csr, cmd) {
				openssl.CASignCSR(csr, csroptions, false, cacrt, cakey, false, function(err, crt, cmd) {
					if(err) {
						console.log(err);
						console.log(cmd);
					} else {
						console.log(crt);
						console.log(cmd);
					}
				});
			});
		});
	});
});*/