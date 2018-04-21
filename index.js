'use strict';
const { spawn } = require( 'child_process' );
const https = require('https');
var tmp = require('tmp');
var fs = require('fs');
const opensslbinpath = 'openssl'; //use full path if not in system PATH
const tempdir = '/tmp/';

var openssl = function() {
	var runOpenSSLCommand = function(cmd, callback) {
		const stdoutbuff = [];
		const stderrbuff = [];
		var terminate = false;
		
		if(cmd.indexOf('s_client') >= 0) {
			terminate = true;
		}
		
		const openssl = spawn( opensslbinpath, cmd.split(' ') );
		
		openssl.stdout.on('data', function(data) {
			stdoutbuff.push(data.toString());
			/*//openssl.stdin.setEncoding('utf-8');
			setTimeout(function() {
				//openssl.stdin.write("QUIT\r");
				//console.log('QUIT\r\n');
				//openssl.stdin.end();
				openssl.kill();
			}, 1000);*/
			if(terminate) {
				openssl.kill();
			}
		});

		/*openssl.stdout.on('end', function(data) {
			stderrbuff.push(data.toString());
		});*/
		
		openssl.stderr.on('data', function(data) {
			stderrbuff.push(data.toString());
		});
		
		openssl.on('exit', function(code) {
			if(terminate && code==null) {
				code = 0;
			}
			var out = {
				command: 'openssl ' + cmd,
				stdout: stdoutbuff.join(''),
				stderr: stderrbuff.join(''),
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
	
	var getSubjectAlternativeNames = function(sans) {
		var names = {}
		var sanarr = sans.content[0].split(', ');
		for(var i = 0; i <= sanarr.length - 1; i++) {
			var san = sanarr[i].split(':');
			var type = san[0];
			var value = san[1];
			//console.log(type + ' - ' + value);
			if(names[type]) {
				names[type].push(value);
			} else {
				names[type] = [value];
			}
		}
		return names;
	}
	
	var getKeyUsage = function(ku) {
		var keyusage = {}
		var index = {
			'Digital Signature': 'digitalSignature',
			'Key Encipherment': 'keyEncipherment',
			'Non Repudiation': 'nonRepudiation',
			'Data Encipherment': 'dataEncipherment',
			'Key Agreement': 'keyAgreement',
			'Certificate Sign': 'keyCertSign',
			'CRL Sign': 'cRLSign',
			'Encipher Only': 'encipherOnly',
			'Decipher Only': 'decipherOnly'
		}
		var keyusages = ku.content[0].split(', ');
		if(ku.critical) keyusage.critical = true;
		keyusage['usages'] = [];
		for(var i = 0; i <= keyusages.length - 1; i++) {
			keyusage['usages'].push(index[keyusages[i]]);
		}
		return keyusage;
	}
	
	var getExtendedKeyUsage = function(eku) {
		var extendedkeyusage = {}
		var index = {
			'TLS Web Server Authentication': 'serverAuth',
			'TLS Web Client Authentication': 'clientAuth',
			'Code Signing': 'codeSigning',
			'E-mail Protection': 'emailProtection',
			'Time Stamping': 'timeStamping',
			'OCSP Signing': 'OCSPSigning',
			'Microsoft Individual Code Signing': 'msCodeInd',
			'Microsoft Commercial Code Signing': 'msCodeCom',
			'Microsoft Trust List Signing': 'msCTLSign',
			'Microsoft Encrypted File System': 'msEFS'
		}
		var extendedkeyusages = eku.content[0].split(', ');
		if(eku.critical) extendedkeyusage.critical = true;
		extendedkeyusage['usages'] = [];
		for(var i = 0; i <= extendedkeyusages.length - 1; i++) {
			extendedkeyusage['usages'].push(index[extendedkeyusages[i]]);
		}
		return extendedkeyusage;
	}
	
	var getBasicConstraints = function(bc) {
		//console.log(bc);
		var basicConstraints = {};
		var constraints = bc.content[0].split(', ');
		if(bc.critical) basicConstraints.critical = true;
		for(var i = 0; i <= constraints.length - 1; i++) {
			var value;
			var constraint = constraints[i].split(':');
			if(constraint[1]=='TRUE') {
				value = true;
			} else if(constraint[1]=='FALSE') {
				value = false
			} else if(!isNaN(constraint[1])) {
				value = parseInt(constraint[1]);
			} else {
				value = constraint[1]
			}
			basicConstraints[constraint[0]] = value;
		}
		return basicConstraints;
	}
	 //this won't work for organization names with a ', '
	/*var getSubject = function(certificate) {
		var subject = {};
		var index = {
			'C': 'countryName',
			'ST': 'stateOrProvinceName',
			'L': 'localityName',
			'postalCode': 'postalCode',
			'street': 'streetAddress',
			'O': 'organizationName',
			'OU': 'organizationalUnitName',
			'CN': 'commonName',
			'emailAddress': 'emailAddress'
		}
		var subjectstr = 'Subject: '
		var findsubject = certificate.split('\n');
		for(var i = 0; i <= findsubject.length - 1; i++) {
			if(findsubject[i].indexOf(subjectstr) >= 0) {
				var subjectline = findsubject[i].substr(findsubject[i].indexOf(subjectstr) + subjectstr.length);
				//console.log(subjectline);
				var subjectarr = subjectline.split(', ');
				for(var j = 0; j <= subjectarr.length - 1; j++) {
					var subsubject = subjectarr[j].split('/');
					for(var k = 0; k <= subsubject.length - 1; k++) {
						var sub = subsubject[k].split('=');
						console.log(sub);
						if(sub[0]=='CN' || sub[0]=='OU') {
							if(subject[index[sub[0]]]) {
								subject[index[sub[0]]].push(sub[1]);
							} else {
								subject[index[sub[0]]] = [sub[1]];
							}
						} else {
							subject[index[sub[0]]] = sub[1];
						}
					}
				}
			}
		}
		console.log(subject);
	}*/
	
	var trimSubjectAttrs = function(values) {
		var trimmed = []
		for(var i = 0; i <= values.length - 1; i++) {
			trimmed.push(values[i].trim());
		}
		return trimmed;
	}
	
	var getSubject = function(certificate) {
		var normalizesubject = {};
		var subject = {};
		var index = {
			'C': 'countryName',
			'ST': 'stateOrProvinceName',
			'L': 'localityName',
			'postalCode': 'postalCode',
			'street': 'streetAddress',
			'O': 'organizationName',
			'OU': 'organizationalUnitName',
			'CN': 'commonName',
			'emailAddress': 'emailAddress'
		}
		var subjectstr = 'Subject: '
		var findsubject = certificate.split('\n');
		for(var i = 0; i <= findsubject.length - 1; i++) {
			if(findsubject[i].indexOf(subjectstr) >= 0) {
				var subjectline = findsubject[i].substr(findsubject[i].indexOf(subjectstr) + subjectstr.length);
				//console.log(subjectline);
				//console.log(subjectline.replace(/\//g, ', '));
				//console.log(subjectline.split('='));
				var subjectarr = subjectline.replace(/\//g, ', ')
				var untrimmedsubject = subjectarr.split('=');
				//console.log(splitsubject);
				var splitsubject = trimSubjectAttrs(untrimmedsubject);
				if(splitsubject[0].split(', ').length > 2) {
					//console.log(splitsubject[j].split(', '));
					value = splitsubject[1].split(', ').slice(0, -1).join(', ');
					type = splitsubject[0]
				} else {
					value = splitsubject[1].split(', ')[0];
					type = splitsubject[0]
				}
				normalizesubject[index[type]] = [value];
				for(var j = 1; j <= splitsubject.length - 2; j++) {
					var type;
					var value;
					if(splitsubject[j + 1].split(', ').length > 2) {
						//console.log(splitsubject[j]);
						//console.log(splitsubject[j].split(', '));
						value = splitsubject[j + 1].split(', ').slice(0, -1).join(', ');
						type = splitsubject[j].split(', ').pop();
						//console.log(type);
						//console.log(value);
					} else {
						value = splitsubject[j + 1].split(', ')[0];
						type = splitsubject[j].split(', ')[splitsubject[j].split(', ').length - 1];
						//console.log(type);
					}
					//console.log(type);
					if(normalizesubject[index[type]]) {
					normalizesubject[index[type]].push(value);
					} else {
						normalizesubject[index[type]] = [value];
					}
				}
			}
		}
		for(var key in normalizesubject) {
			if(normalizesubject[key].length==1) {
				subject[key] = normalizesubject[key][0];
			} else {
				subject[key] = normalizesubject[key];
			}
		}
		return subject;
	}
	
	var getx509v3Attributes = function(certificate) {
		var extensions = {}
		var parsedextensions = {};
		//console.log(certificate);
		var x509v3 = certificate.split('\n');
		for(var i = 0; i <= x509v3.length - 1; i++) {
			if(x509v3[i].indexOf('X509v3') >= 0 || x509v3[i].indexOf('CT Precertificate SCTs') >= 0 || x509v3[i].indexOf('Authority Information Access') >= 0 ) {
				var ext = x509v3[i].split(':');
				var extname = ext[0].replace('X509v3','').trim();
				var critical = false;
				if(ext[1]==' critical') critical = true; 
				//console.log(i + ' - ' + extname + ' - ' + critical);
				parsedextensions[extname] = { "critical": critical, "content": []};
			} else {
				if(parsedextensions[extname]) {
					parsedextensions[extname].content.push(x509v3[i].trim());
				}
			}
		}
		for(var key in parsedextensions) {
			if(key=='Subject Alternative Name') {
				extensions['SANs'] = getSubjectAlternativeNames(parsedextensions[key]);
			} else if(key=='Key Usage') {
				extensions['keyUsage'] = getKeyUsage(parsedextensions[key]);
			} else if(key=='Extended Key Usage') {
				extensions['extendedKeyUsage'] = getExtendedKeyUsage(parsedextensions[key]);
			} else if(key=='Basic Constraints') {
				extensions['basicConstraints'] = getBasicConstraints(parsedextensions[key]);
			}
		}
		return extensions;
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
	
	this.getCertFromNetwork = function(options, callback) {
		const begin = '-----BEGIN CERTIFICATE-----';
		const end = '-----END CERTIFICATE-----';
		options.port = typeof options.port !== 'undefined' ? options.port : 443;
		options.starttls = typeof options.starttls !== 'undefined' ? options.starttls : false;
		options.protocol = typeof options.protocol !== 'undefined' ? options.protocol : 'https';
		
		var command;
		var param;
		
		if(options.protocol=='https') {
			param = ' -servername ' + options.hostname;
		} else if(options.starttls){
			param = ' -starttls ' + options.protocol;
		} else {
			param = '';
		}
		command = 's_client -connect ' + options.hostname + ':' + options.port + param;
		runOpenSSLCommand(command, function(err, out) {
			if(err) {
				callback(err, false, 'openssl ' + command);
			} else {
				try {
					var certificate = begin + out.stdout.split(begin)[1].split(end)[0] + end;
				} catch(e) {
					callback('No certificate found in openssl command response', 'No certificate found in openssl command response', 'openssl ' + command);
					return;
				}
				callback(false, certificate, 'openssl ' + command);
			}
		});
		//console.log(options);
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
						var extensions = getx509v3Attributes(out.stdout);
						var subject = getSubject(out.stdout);
						var csroptions = {
							extensions: extensions,
							subject: subject
						}
						//callback(false,out.stdout,cmd.join());
						callback(false,csroptions,'openssl ' + cmd.join().replace(path, 'cert.crt'));
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
								cmd = ['pkcs12 -passin pass:' + pass + ' -in ' + path + ' -nocerts -nodes'];
								runOpenSSLCommand(cmd.join(' '), function(err, out) {
									if(err) {
										callback(out.stderr,false);
										console.log(out);
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
	
	var convertToPKCS1 = function(key, encryption, callback) {
		//console.log(key);
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var cmd = ['rsa -in ' + path];
				if(encryption) {
					cmd.push('-' + encryption.cipher + ' -passin pass:' + encryption.password + ' -passout pass:' + encryption.password);// + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
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
	
	var generateConfig = function(options, cert, callback) {
		options.hash = typeof options.hash !== 'undefined' ? options.hash : 'sha256';
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
			'msCTLSign',
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
		//if(options.extensions) {
			req.push('req_extensions = req_ext');
		//}
		if(options.subject) {
			req.push('distinguished_name = req_distinguished_name');
			req.push('[ req_distinguished_name ]');
			for (var prop in options.subject) {
				//console.log(prop + typeof(options.subject[prop]));
				if(validsubject.indexOf(prop) >=0 ) {
					//if(prop=='commonName' || prop=='organizationalUnitName') {
					if(typeof(options.subject[prop]) != 'string') {
						for(var i = 0; i <= options.subject[prop].length - 1; i++) {
							req.push(i + '.' + prop + ' = ' + options.subject[prop][i]);
						}
					} else {
						req.push(prop + ' = ' + options.subject[prop]);
					}
				} else {
					callback('Invalid subject: ' + prop, false);
					return false;
				}
			}
		}
		req.push('[ req_ext ]');
		if(options.extensions) {
			//req.push('[ req_ext ]');
			for(var ext in options.extensions) {
				if(ext == 'SANs') {
					var sansatend = [];
					sansatend.push('subjectAltName = @alt_names');
					sansatend.push('[ alt_names ]');
					for(var type in options.extensions[ext]) {
						if(validsantypes.indexOf(type) >= 0) {
							for(var i = 0; i <= options.extensions[ext][type].length - 1; i++) {
								sansatend.push(type + '.' + i  + ' = ' + options.extensions[ext][type][i]);
							}
						} else {
							callback('Invalid ' + ext + ': ' + options.extensions[ext].usages[i], false);
							return false;
						}
					}
				} else if (ext == 'extendedKeyUsage') {
					var critical = '';
					var valid = 0;
					for(var i = 0; i <= options.extensions[ext].usages.length - 1; i++) {
						if(validextkeyusage.indexOf(options.extensions[ext].usages[i]) < 0) {
							callback('Invalid ' + ext + ': ' + options.extensions[ext].usages[i], false);
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
							callback('Invalid ' + ext + ': ' + options.extensions[ext].usages[i], false);
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
								callback('Provided ' + ext + ' parameter \'' + type + '\' is type ' + typeof(options.extensions[ext][type]) + ', ' + reqtype + ' required', false);
								return false;
							}
							//console.log(options.extensions[ext][type]);
						} else if(type=='CA') {
							var reqtype = 'boolean';
							if(typeof(options.extensions[ext][type]) == reqtype) {
								if (options.extensions[ext][type]) {
									bccmd.push('CA:true');
									if(cert) {
										req.push('subjectKeyIdentifier = hash');
										req.push('authorityKeyIdentifier = keyid:always,issuer');
									}
								} else {
									bccmd.push('CA:false');
								}
								valid++;
							} else {
								callback('Provided ' + ext + ' parameter \'' + type + '\' is type ' + typeof(options.extensions[ext][type]) + ', ' + reqtype + ' required', false);
								return false;
							}
						} else if(type=='pathlen') {
							var reqtype = 'number';
							if(typeof(options.extensions[ext][type]) == reqtype) {
								if (options.extensions[ext][type] >= 0) {
									bccmd.push('pathlen:' + options.extensions[ext][type]);
								} else {
									//optional pathlen not defined
								}
								valid++;
							} else {
								callback('Provided ' + ext + ' parameter \'' + type + '\' is type ' + typeof(options.extensions[ext][type]) + ', ' + reqtype + ' required', false);
								return false;
							}
						} else {
							callback('Invalid ' + ext + ': ' + type, false);
							return false;
						}
					}
					if(valid > 0) {
						req.push('basicConstraints=' + bccmd.join(','));
					}
					if(valid == 1 && bccmd[0]=='critical') {
						callback('Basic constraints cannot contain only \'critical\'', false);
						return false;
					}
				} else {
					callback('Invalid extension: ' + ext, false);
					return false;
				}
			}
			if(sansatend) {
				for(var i = 0; i <= sansatend.length - 1; i++) {
					req.push(sansatend[i]);
				}
			}
		}
		callback(false, req);
		//console.log(req);
	}
	
	this.createPKCS7 = function(certs, callback) {
		//console.log(typeof(certs));
		var cmd = ['crl2pkcs7 -nocrl']
		var files = [];
		for(var i = 0; i <= certs.length - 1; i++) {
			var name = tmp.tmpNameSync();
			files.push(name);
			fs.writeFileSync(name, certs[i]);
			cmd.push('-certfile ' + name);
		}
		runOpenSSLCommand(cmd.join(' '), function(err, out) {
			for(var i = 0; i <= files.length - 1; i++) {
				fs.unlinkSync(files[i]);
			}
			if(err) {
				//console.log(out.command);
				callback(err, out.stdout, {
					command: [out.command]
				});
			} else {
				//console.log(out.command);
				callback(false, out.stdout, {
					command: [out.command]
				});
			}
		});
	}
	
	var generatePKCS12 = function(certpath, keypath, passin, passout, capath, callback) {
		tmp.file(function _tempFileCreated(err, pfxpath, fd, cleanupCallback) {
			if (err) throw err;
			var cmd = ['pkcs12 -export -out ' + pfxpath + ' -inkey ' + keypath + ' -in ' + certpath];
			if(passout) {
				cmd.push('-passout pass:' + passout);
			} else {
				cmd.push('-nodes -passout pass:');
			}
			if(passin) {
				cmd.push('-passin pass:' + passin);
			} else {
				cmd.push('-passin pass:');
			}
			if(capath) {
				cmd.push('-certfile ' + capath);
			}
			runOpenSSLCommand(cmd.join(' '), function(err, out) {
				if(err) {
					//console.log(out.command);
					callback(err, out.stdout, {
						command: [out.command.replace(keypath, 'rsa.key').replace(certpath, 'cert.crt').replace(pfxpath, 'cert.pfx').replace(capath, 'ca.crt') + ' -out cert.pfx']
					});
				} else {
					fs.readFile(pfxpath, function(err, data) {
						//console.log(out.command);
						callback(false, data, {
							command: [out.command.replace(keypath, 'rsa.key').replace(certpath, 'cert.crt').replace(pfxpath, 'cert.pfx').replace(capath, 'ca.crt') + ' -out cert.pfx']
						});
					});
				}
			});
		});
	}
	
	this.createPKCS12 = function(cert, key, passin, passout, ca, callback) {
		tmp.file(function _tempFileCreated(err, certpath, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(certpath, cert, function() {
				tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback) {
					if (err) throw err;
					fs.writeFile(keypath, key, function() {
						if(ca) {
							tmp.file(function _tempFileCreated(err, capath, fd, cleanupCallback) {
								if (err) throw err;
								fs.writeFile(capath, ca, function() {
									generatePKCS12(certpath, keypath, passin, passout, capath, function(err, pfx, command) {
										callback(err, pfx, command);
									});
								});
							});
						} else {
							generatePKCS12(certpath, keypath, passin, passout, false, function(err, pfx, command) {
								callback(err, pfx, command);
							});
						}
					});
				});
			});
		});
	}
	
	this.CASignCSR = function(csr, options, serial, ca, key, password, callback) {
		//console.log(csr);
		options.days = typeof options.days !== 'undefined' ? options.days : 365;
		generateConfig(options, true, function(err, req) {
			if(err) {
				callback(err,{
					command: null,
					data: null
				});
				return false;
			} else {
				tmp.file(function _tempFileCreated(err, capath, fd, cleanupCallback) {
					if (err) throw err;
					fs.writeFile(capath, ca, function() {
						tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback) {
							if (err) throw err;
							fs.writeFile(csrpath, csr, function() {
								tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback) {
									if (err) throw err;
									fs.writeFile(keypath, key, function() {
										tmp.file(function _tempFileCreated(err, csrconfig, fd, cleanupCallback) {
											if (err) throw err;
											fs.writeFile(csrconfig, req.join('\r\n'), function() {
												var path;
												if(serial) {
													path = serial;
												} else {
													path = tmp.tmpNameSync();
												}
												var cmd = ['x509 -req -in ' + csrpath + ' -days ' + options.days + ' -CA ' + capath + ' -CAkey ' + keypath + ' -extfile ' + csrconfig + ' -extensions req_ext -CAserial ' + path + ' -CAcreateserial'];
												if(password) {
													cmd.push('-passin pass:' + password);
												}
										
										//console.log(cmd);
										
												runOpenSSLCommand(cmd.join(' '), function(err, out) {
													if(err) {
														callback(err, out.stdout, {
															command: [out.command.replace(keypath, 'rsa.key').replace(csrpath, 'cert.csr').replace(capath, 'ca.crt').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
															files: {
																config: req.join('\r\n')
															}
														});
													} else {
														fs.readFile(path, function(err, serial) {
															callback(false, out.stdout, {
																command: [out.command.replace(keypath, 'rsa.key').replace(csrpath, 'cert.csr').replace(capath, 'ca.crt').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
																serial: serial,
																files: {
																	config: req.join('\r\n')
																}
															});
														});
													}
													if(!serial) {
														fs.unlink(path, function(err) {
															//delete temp serial file
														});
													}
												});
											});
										});
									});
								});
							});
						});
					});
				});
			}
		});
	}
	
	this.selfSignCSR = function(csr, options, key, password, callback) {
		//console.log(csr);
		options.days = typeof options.days !== 'undefined' ? options.days : 365;
		generateConfig(options, true, function(err, req) {
			if(err) {
				callback(err,{
					command: null,
					data: null
				});
				return false;
			} else {
				tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback) {
					if (err) throw err;
					fs.writeFile(csrpath, csr, function() {
						tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback) {
							if (err) throw err;
							fs.writeFile(keypath, key, function() {
								tmp.file(function _tempFileCreated(err, csrconfig, fd, cleanupCallback) {
									if (err) throw err;
									fs.writeFile(csrconfig, req.join('\r\n'), function() {
										var cmd = ['req -x509 -nodes -in ' + csrpath + ' -days ' + options.days + ' -key ' + keypath + ' -config ' + csrconfig + ' -extensions req_ext'];
										if(password) {
											cmd.push('-passin pass:' + password);
										}
								
								//console.log(cmd);
								
										runOpenSSLCommand(cmd.join(' '), function(err, out) {
											if(err) {
												callback(err, out.stdout, {
													command: [out.command.replace(keypath, 'rsa.key').replace(csrpath, 'cert.csr').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
													files: {
														config: req.join('\r\n')
													}
												});
											} else {
												callback(false, out.stdout, {
													command: [out.command.replace(keypath, 'rsa.key').replace(csrpath, 'cert.csr').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
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
					});
				});	
			}
		});
	}
	
	this.generateCSR = function(options, key, password, callback) {
		generateConfig(options, false, function(err, req) {
			if(err) {
				callback(err,{
					command: null,
					data: null
				});
				return false;
			} else {
				tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback) {
					if (err) throw err;
					fs.writeFile(keypath, key, function() {
						tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback) {
							if (err) throw err;
							fs.writeFile(csrpath, req.join('\r\n'), function() {
								var cmd = ['req -new -nodes -key ' + keypath + ' -config ' + csrpath];
								if(password) {
									cmd.push('-passin pass:' + password);
								}
						
						//console.log(cmd);
						
								runOpenSSLCommand(cmd.join(' '), function(err, out) {
									if(err) {
										callback(err, out.stdout, {
											command: [out.command.replace(keypath, 'rsa.key').replace(csrpath, 'csrconfig.txt') + ' -out cert.csr'],
											files: {
												config: req.join('\r\n')
											}
										});
									} else {
										callback(false, out.stdout, {
											command: [out.command.replace(keypath, 'rsa.key').replace(csrpath, 'csrconfig.txt') + ' -out cert.csr'],
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
