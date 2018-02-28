'use strict';
const { spawn } = require( 'child_process' );
const https = require('https');
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
	
	var pemEncode = function(str, n) {
		var ret = []

		for (var i = 1; i <= str.length; i++) {
			ret.push(str[i - 1])
			var mod = i % n

			if (mod === 0) {
				ret.push('\n')
			}
		}

		var returnString = '-----BEGIN CERTIFICATE-----\n' + ret.join('') + '\n-----END CERTIFICATE-----'

		return returnString;
	}
	
	var isEmpty = function (object) {
		for (var prop in object) {
			if (object.hasOwnProperty(prop)) return false;
		}

		return true;
	}
	
	this.getCertFromURL = function(url, callback) {
		if (url.length <= 0 || typeof url !== 'string') {
			callback('Invalid URL','Invalid URL');
		}
		
		var options = {
			hostname: url,
			agent: false,
			rejectUnauthorized: false,
			ciphers: 'ALL'
		}
		
		var req = https.get(options, function(res) {
			var certificate = res.socket.getPeerCertificate()
			if (isEmpty(certificate) || certificate === null) {
				reject({ message: 'The website did not provide a certificate' })
			} else {
				if (certificate.raw) {
					certificate.pemEncoded = pemEncode(certificate.raw.toString('base64'), 64)
				}
				callback(false,certificate);
				return true;
			}
		});
		
		req.on('error', function(e) {
			callback(e,false);
		});

		req.end();
	}
	
	this.convertCertToCSR = function(cert, callback) {
		var cmd = [];
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				cmd.push('x509 -in ' + path + ' -text -noout');
				runOpenSSLCommand(cmd.join(), function(err, out) {
					if(err) {
						callback(true,out.stderr,cmd.join());
					} else {
						callback(false,out.stdout,cmd.join());
					}
				});
			});
		});
	}
	
	var importRSAPrivateKey = function(key, password, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var pass = '';
				if(password) {
					pass = password;
				}
				var cmd = ['rsa -passin pass:' + pass + ' -in ' + path];
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					if(err) {
						cmd.push('-inform DER');
						runOpenSSLCommand(cmd.join(' '), function(err, out) {
							if(err) {
								callback(true,out.stderr);
							} else {
								convertToPKCS8(out.stdout, false, function(err, key) {
									callback(false,key.data);
								});
							}
						});
					} else {
						convertToPKCS8(out.stdout, false, function(err, key) {
							callback(false,key.data);
						});
					}
				});
			});
		});
	}
	
	this.importRSAPrivateKey = function(key, password, callback) {
		importRSAPrivateKey(key, password, callback);
	}
	
	var convertToPKCS1 = function(key, password, callback) {
		//console.log(key);
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var cmd = ['rsa -in ' + path];
				if(password) {
					cmd.push('-passin pass:' + password);// + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
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
	
	var convertToPKCS8 = function(key, password, callback) {
		//console.log(key);
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var cmd = ['pkcs8 -topk8 -inform PEM -outform PEM -in ' + path];
				if(password) {
					cmd.push('-passin pass:' + password);// + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
				} else {
					cmd.push('-nocrypt');
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
	
	this.generateCSR = function(options, key, password, callback) {
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
							callback('Invalid ' + ext + ': ' + options.extensions[ext].usages[i],{
								command: null,
								data: null
							});
							return false;
						}
					}
				} else if (ext == 'extendedKeyUsage') {
					var critical = '';
					var valid = 0;
					for(var i = 0; i <= options.extensions[ext].usages.length - 1; i++) {
						if(validextkeyusage.indexOf(options.extensions[ext].usages[i]) < 0) {
							callback('Invalid ' + ext + ': ' + options.extensions[ext].usages[i],{
								command: null,
								data: null
							});
							return false;
						} else {
							valid++;
						}
					}
					if(valid > 0) {
						if(options.extensions[ext].critical) critical = 'critical,';
						req.push(ext + '=' + critical + options.extensions[ext].usages.join(','));
					}
				} else if (ext == 'keyUsage') {
					var critical = '';
					var valid = 0;
					for(var i = 0; i <= options.extensions[ext].usages.length - 1; i++) {
						//console.log(options.extensions[ext]);
						if(validkeyusage.indexOf(options.extensions[ext].usages[i]) < 0) {
							callback('Invalid ' + ext + ': ' + options.extensions[ext].usages[i],{
								command: null,
								data: null
							});
							return false;
						} else {
							valid++;
						}
					}
					if(valid > 0) {
						if(options.extensions[ext].critical) critical = 'critical,';
						req.push(ext + '=' + critical + options.extensions[ext].usages.join(','));
					}
				} else if (ext == 'basicConstraints') {
					var bccmd = [];
					var valid = 0;
					for(var type in options.extensions[ext]) {
						if(type=='critical') {
							var reqtype = 'boolean';
							if(typeof(options.extensions[ext][type]) == reqtype) {
								if (options.extensions[ext][type]) {
									bccmd.unshift('critical');
								} else {
									//not critical
								}
								valid++;
							} else {
								callback('Provided ' + ext + ' parameter \'' + type + '\' is type ' + typeof(options.extensions[ext][type]) + ', ' + reqtype + ' required',{
									command: null,
									data: null
								});
								return false;
							}
							//console.log(options.extensions[ext][type]);
						} else if(type=='CA') {
							var reqtype = 'boolean';
							if(typeof(options.extensions[ext][type]) == reqtype) {
								if (options.extensions[ext][type]) {
									bccmd.push('CA:true');
								} else {
									bccmd.push('CA:false');
								}
								valid++;
							} else {
								callback('Provided ' + ext + ' parameter \'' + type + '\' is type ' + typeof(options.extensions[ext][type]) + ', ' + reqtype + ' required',{
									command: null,
									data: null
								});
								return false;
							}
						} else if(type=='pathlen') {
							var reqtype = 'number';
							if(typeof(options.extensions[ext][type]) == reqtype) {
								if (options.extensions[ext][type]) {
									bccmd.push('pathlen:' + options.extensions[ext][type]);
								} else {
									//optional pathlen not defined
								}
								valid++;
							} else {
								callback('Provided ' + ext + ' parameter \'' + type + '\' is type ' + typeof(options.extensions[ext][type]) + ', ' + reqtype + ' required',{
									command: null,
									data: null
								});
								return false;
							}
						} else {
							callback('Invalid ' + ext + ': ' + type,{
								command: null,
								data: null
							});
							return false;
						}
					}
					if(valid > 0) {
						req.push('basicConstraints=' + bccmd.join(','));
					}
					if(valid == 1 && bccmd[0]=='critical') {
						callback('Basic constraints cannot contain only \'critical\'', {
							command: null,
							data: null
						});
						return false;
					}
				} else {
					callback('Invalid extension: ' + ext,{
						command: null,
						data: null
					});
					return false;
				}
			}
		}
		//console.log(req);
		
		tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(keypath, key, function() {
				tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback) {
					if (err) throw err;
					fs.writeFile(csrpath, req.join('\r\n'), function() {
						var cmd = ['req -new -new -nodes -key ' + keypath + ' -config ' + csrpath];
						if(password) {
							cmd.push('-passin pass:' + password);
						}
				
				//console.log(cmd);
				
						runOpenSSLCommand(cmd.join(' '), function(err, out) {
							if(err) {
								callback(err, out.stdout, {
									command: [out.command.replace(keypath, 'rsa.key')],
									files: {
										config: req.join('\r\n')
									}
								});
							} else {
								callback(false, out.stdout, {
									command: [out.command.replace(keypath, 'rsa.key').replace(csrpath, 'config.txt'),],
									files: {
										config: req.join('\r\n')
									}
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
				//console.log(out);
				callback(false, out.stdout, [out.command + ' -out rsa.key']);
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
							callback(false, out.data, [ outkey.command + ' -out rsa.key', out.command + ' -out rsa.key' ]);
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