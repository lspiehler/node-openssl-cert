'use strict';
const { spawn } = require( 'child_process' )
var tmp = require('tmp');
var fs = require('fs');
const opensslbinpath = 'openssl'; //use full path if not is system PATH
const tempdir = '/tmp/';

var openssl = function() {
	var runOpenSSLCommand = function(cmd, callback) {
		const stdoutbuff = [];
		const stderrbuff = [];
		
		const openssl = spawn( opensslbinpath, cmd.split(' ') );
		
		openssl.stdout.on('data', function(data) {
			stdoutbuff.push(data.toString());
		});

		/*openssl.stdout.on('end', function(data) {
			stderrbuff.push(data.toString());
		});*/
		
		openssl.stderr.on('data', function(data) {
			stderrbuff.push(data.toString());
		});
		
		openssl.on('exit', function(code) {
			var out = {
				command: 'openssl ' + cmd,
				stdout: stdoutbuff.join(),
				stderr: stderrbuff.join(),
				exitcode: code
			}
			if (code != 0) {
				callback(stderrbuff.join(), out);
			} else {
				callback(false, out);
			}
		});
	}
	
	var convertToPKCS1 = function(key, encryption, callback) {
		//console.log(key);
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var cmd = ['rsa -in ' + path];
				if(encryption) {
					cmd.push('-passin pass:' + encryption.password + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
				}
				//console.log(cmd);
				
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					if(err) {
						callback(err,{
							command: out.command.replace(path, 'rsa.key'),
							data: out.stdout
						});
					} else {
						callback(false,{
							command: out.command.replace(path, 'rsa.key'),
							data: out.stdout
						});
					}
				});
			});
		});
	}
	
	this.generateCSR = function(options, key, callback) {
		const validopts = [
			'hash',
			'subject'
		];
		const validkeyusage = [
			'keyCertSign', //CA Only
			'cRLSign', //CA Only
			'digitalSignature',
			'nonRepudiation',
			'keyEncipherment',
			'dataEncipherment',
			'keyAgreement',
			'encipherOnly',
			'decipherOnly'
		]

		const validextkeyusage = [
			'serverAuth',
			'clientAuth',
			'codeSigning',
			'emailProtection',
			'timeStamping',
			'OCSPSigning',
			'msCodeInd',
			'msCodeCom',
			'mcCTLSign',
			'msEFS',
			'ipsecIKE'
		]
		
		const validsubject = [
			'countryName',
			'stateOrProvinceName',
			'localityName',
			'postalCode',
			'streetAddress',
			'organizationName',
			'organizationalUnitName',
			'commonName',
			'emailAddress'
		];
		const validsantypes = [
			'DNS',
			'IP',
			'URI',
			'email',
			'otherName'
		];
		var req = [
			'[ req ]',
			'default_md = ' + options.hash,
			'prompt = no'
		]
		if(options.extensions) {
			req.push('req_extensions = req_ext');
		}
		if(options.subject) {
			req.push('distinguished_name = req_distinguished_name');
			req.push('[ req_distinguished_name ]');
			for (var prop in options.subject) {
				if(validsubject.indexOf(prop) >=0 ) {
					if(prop=='commonName') {
						for(var i = 0; i <= options.subject[prop].length - 1; i++) {
							req.push(i + '.' + prop + ' = ' + options.subject[prop][i]);
						}
					} else {
						req.push(prop + ' = ' + options.subject[prop]);
					}
				} else {
					callback('Invalid subject: ' + prop,{
						command: null,
						data: null
					});
					return false;
				}
			}
		}
		if(options.extensions) {
			req.push('[ req_ext ]');
			for(var ext in options.extensions) {
				if(ext == 'SANs') {
					req.push('subjectAltName = @alt_names');
					req.push('[ alt_names ]');
					for(var type in options.extensions[ext]) {
						if(validsantypes.indexOf(type) >= 0) {
							for(var i = 0; i <= options.extensions[ext][type].length - 1; i++) {
								req.push(type + '.' + i  + ' = ' + options.extensions[ext][type][i]);
							}
						} else {
							console.log('Invalid SAN type');
						}
					}
				} else if (ext == 'extendedKeyUsage') {
					var valid = 0;
					for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
						if(validextkeyusage.indexOf(options.extensions[ext][i]) < 0) {
							callback('Invalid ' + ext + ': ' + extkeyusage,{
								command: null,
								data: null
							});
							return false;
						} else {
							valid++;
						}
					}
					if(valid > 0) {
						req.push(ext + '=' + options.extensions[ext].join(','));
					}
				} else if (ext == 'keyUsage') {
					var valid = 0;
					for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
						//console.log(options.extensions[ext]);
						if(validkeyusage.indexOf(options.extensions[ext][i]) < 0) {
							callback('Invalid ' + ext + ': ' + options.extensions[ext][i],{
								command: null,
								data: null
							});
							return false;
						} else {
							valid++;
						}
					}
					if(valid > 0) {
						req.push(ext + '=' + options.extensions[ext].join(','));
					}
				} else if (ext == 'basicConstraints') {

				} else {
					callback('Invalid extension: ' + ext,{
						command: null,
						data: null
					});
					return false;
				}
			}
		}
		console.log(req);
		
		tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(keypath, key.data, function() {
				tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback) {
					if (err) throw err;
					fs.writeFile(csrpath, req.join('\r\n'), function() {
						var cmd = ['req -new -new -nodes -sha256 -key ' + keypath + ' -config ' + csrpath];
						if(key.encryption.isencrypted) {
							cmd.push('-passin pass:' + key.encryption.password);
						}
				
				//console.log(cmd);
				
						runOpenSSLCommand(cmd.join(' '), function(err, out) {
							if(err) {
								callback(err,{
									command: [out.command.replace(keypath, 'rsa.key')],
									data: out.stdout
								});
							} else {
								callback(false,{
									command: [out.command.replace(keypath, 'rsa.key')],
									data: out.stdout
								});
							}
						});
					});
				});
			});
		});
	}
	
	this.generateRSAPrivateKey = function(options, callback) {
		const type = 'RSA';
		let pkeyopt = [];
		var encryption = false;
		let validoptions = [
			'rsa_keygen_bits',
			'rsa_keygen_primes',
			'rsa_keygen_pubexp',
			'format',
			'encryption'
		]
		
		let cmd = ['genpkey -outform PEM -algorithm RSA'];
		
		options.rsa_keygen_bits = typeof options.rsa_keygen_bits !== 'undefined' ? options.rsa_keygen_bits : 2048;
		options.rsa_keygen_primes = typeof options.rsa_keygen_primes !== 'undefined' ? options.rsa_keygen_primes : false;
		options.rsa_keygen_pubexp = typeof options.rsa_keygen_pubexp !== 'undefined' ? options.rsa_keygen_pubexp : false;
		options.format = typeof options.format !== 'undefined' ? options.format : 'PKCS8';
		if(options.encryption) {
			encryption = true;
			options.encryption.password = typeof options.encryption.password !== 'undefined' ? options.encryption.password : 'test123';
			options.encryption.cipher = typeof options.encryption.cipher !== 'undefined' ? options.encryption.cipher : 'des3';
		} else {
			options.encryption = false;
		}
		
		for (var option in options) {
			if(validoptions.indexOf(option) >= 0) {
				if(option=='encryption' && options[option]) {
					cmd.push('-pass pass:' + options[option].password + ' -' + options[option].cipher);
				} else if(options[option] && option.indexOf('rsa_keygen_') == 0) {
					cmd.push('-pkeyopt ' + option + ':' + options[option]);
				}
			} else {
				callback('Invalid option ' + option , 'Invalid option ' + option );
				return;
			}
		}
		
		if(options.format=='PKCS8') {
			runOpenSSLCommand(cmd.join(' '), function(err, out) {
				console.log(out);
				callback(false, new privatekey(type, options.rsa_keygen_bits, options.encryption, out.stdout), [out.command + ' -out rsa.key']);
			});
		} else if (options.format == 'PKCS1' ) {
			runOpenSSLCommand(cmd.join(' '), function(err, outkey) {
				if(err) {
					callback(err, false);
				} else {
					convertToPKCS1(outkey.stdout, options.encryption, function(err, out) {
						if(err) {
							callback(err, false);
						} else {
							callback(false, new privatekey(type, options.rsa_keygen_bits, options.encryption, out.data), [ outkey.command + ' -out rsa.key', out.command + ' -out rsa.key' ]);
						}
					});
				}
			});
		} else {
			callback('Invalid format ' + options.format, 'Invalid format ' + options.format );
				return;
		}
	}
	
	let privatekey = function(type, length, encryption, data) {
		this.keytype = type;
		this.length = length;
		this.encryption = {
			isencrypted: false,
		}
		if(encryption) {
			this.encryption.isencrypted = true;
			this.encryption.password = encryption.password;
		}
		this.data = data;
	}
}

module.exports = openssl;