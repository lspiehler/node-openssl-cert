'use strict';
const { spawn } = require( 'child_process' );
const https = require('https');
const http = require('http');
var tmp = require('tmp');
var fs = require('fs');
var opensslbinpath = 'openssl'; //use full path if not in system PATH
const tempdir = '/tmp/';
var moment = require('moment');
var net = require('net');

var openssl = function(options) {
	
	if(options) {
		if(options.binpath) {
			opensslbinpath = options.binpath;
		} else {
			
		}
	} else {
		
	}
	
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
				//if(data.toString().indexOf('Verify return code: 0 (ok)') >= 0 ) {
				if(stdoutbuff.join('').toString().indexOf('Verify return code: ') >= 0 ) {
					openssl.kill();
				}
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
			var type;
			if(san[0]=='IP Address') {
				type = 'IP';
			} else {
				type = san[0];
			}
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
			'Microsoft Encrypted File System': 'msEFS',
			'ipsec Internet Key Exchange': 'ipsecIKE',
			'IPSec End System': 'ipsecEndSystem',
			'IPSec Tunnel': 'ipsecTunnel',
			'IPSec User': 'ipsecUser'
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
	
	this.getDistinguishedName = function(subjectobj) {
		var index = {
			'countryName': 'C',
			'stateOrProvinceName': 'ST',
			'localityName': 'L',
			'postalCode': 'postalCode',
			'streetAddress': 'street',
			'organizationName': 'O',
			'organizationalUnitName': 'OU',
			'commonName': 'CN',
			'emailAddress': 'emailAddress'
		}
		
		let dn = [];
		
		var keys = Object.keys(subjectobj);
		for(let i = 0; i <= keys.length - 1; i++) {
			if(typeof(subjectobj[keys[i]])=='string') {
				dn.push('/' + index[keys[i]] + '=' + subjectobj[keys[i]])
			} else {
				for(let j = 0; j <= subjectobj[keys[i]].length - 1; j++) {
					dn.push('/' + index[keys[i]] + '=' + subjectobj[keys[i]][j]);
				}
			}
		}	
		return dn.join('');
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
		//console.log(normalizesubject);
		for(var key in normalizesubject) {
			//console.log(typeof(normalizesubject[key]));
			if(normalizesubject[key].length==1) {
				subject[key] = normalizesubject[key][0].replace(/\"/g, '');
			} else {
				//subject[key] = normalizesubject[key].replace(/\"/g, '');
				subject[key] = [];
				for(let i = 0; i <= normalizesubject[key].length - 1; i++) {
					subject[key].push(normalizesubject[key][i].replace(/\"/g, ''));
				}
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
			if(x509v3[i].indexOf('X509v3') >= 0 || x509v3[i].indexOf('CT Precertificate SCTs') >= 0 || x509v3[i].indexOf('Authority Information Access') >= 0 || x509v3[i].indexOf('TLS Feature') >= 0 ) {
				var ext = x509v3[i].split(':');
				var extname = ext[0].replace('X509v3','').trim();
				//console.log(extname);
				var critical = false;
				if(ext[1].replace('\r\n').replace('\n').trim()=='critical') {
					critical = true;
					//console.log('critical');
					parsedextensions[extname] = { "critical": critical, "content": []};
				} else {
					parsedextensions[extname] = { "content": []};
				}
				//console.log(i + ' - ' + extname + ' - ' + critical);
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
			} else if(key=='TLS Feature') {
				extensions['tlsfeature'] = getTLSFeature(parsedextensions[key]);
				//console.log(parsedextensions[key]);
			}
		}
		return extensions;
	}
	
	var getTLSFeature = function(feature) {
		var tlsfeature = []
		var index = {
			'status_request': 'status_request',
		}
		var tlsfeatures = feature.content[0].split(', ');
		for(var i = 0; i <= tlsfeatures.length - 1; i++) {
			tlsfeature.push(index[tlsfeatures[i]]);
		}
		return tlsfeature;
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
	
	var tcpCheck = function(host, port, callback) {
		let option = {
			host: host,
			port: port
		}
		
		var client = net.createConnection(option, function () {
			//console.log('Connection local address : ' + client.localAddress + ":" + client.localPort);
			//console.log('Connection remote address : ' + client.remoteAddress + ":" + client.remotePort);
		});
		
		client.setTimeout(3000);
		client.setEncoding('utf8');
		
		client.on('timeout', function () {
			//console.log('Client connection timeout. ');
			client.destroy();
			callback('Timed out connecting to host ' + host + ' on port ' + port, 'Timed out connecting to host ' + host + ' on port ' + port);
		});
		
		client.on('connect', function () {
			//console.log('Client connected. ');
			client.end();
		});
		
		client.on('error', function (e) {
			//console.log('Client connection error: ' + e);
			if(e.code=='ENOTFOUND') {
				callback('Failed to lookup domain name ' + host, 'Failed to lookup domain name ' + host)
			} else if(e.code=='ECONNRESET') {
				//let openssl handle errors for resets
				callback(false, 'Connection was reset.');
			} else {
				callback('Failed connecting to host ' + host + ' on port ' + port, 'Failed connecting to host ' + host + ' on port ' + port);
			}
		});
		
		client.on('end', function () {
			//console.log('Client connection timeout. ');
			callback(false, 'Successfully established connection.')
		});
		
		client.on('close', function () {
			//console.log('Client connection closed. ');
			//callback(false, 'Successfully established connection.')
		});
		
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
		command = 's_client -showcerts -connect ' + options.hostname + ':' + options.port + param;
		tcpCheck(options.hostname, options.port, function(err, result) {
			if(err) {
				callback(err, false, false);
			} else {
				runOpenSSLCommand(command, function(err, out) {
					if(err) {
						callback(err, false, 'openssl ' + command);
					} else {
						var placeholder = out.stdout.indexOf(begin);
						var certs = [];
						var endoutput = false;
						if(placeholder <= 0) {
							endoutput = true;
							callback('No certificate found in openssl command response', 'No certificate found in openssl command response', 'openssl ' + command);
							return;
						}
						var shrinkout = out.stdout.substring(placeholder);
						//console.log(shrinkout);
						while(!endoutput) {
							let endofcert = shrinkout.indexOf(end);
							certs.push(shrinkout.substring(0, endofcert) + end);
							shrinkout = shrinkout.substring(endofcert); 
							
							placeholder = shrinkout.indexOf(begin);
							//console.log(placeholder);
							if(placeholder <= 0) {
								endoutput = true;
							} else {
								shrinkout = shrinkout.substring(placeholder);
							}
						}
						callback(false, certs, 'openssl ' + command);
						return;
					}
				});
			}
		});
	}
	
	var convertTime = function(line) {
		let timestr = Array();
		for(let i = 1; i <= line.length - 1; i++) {
			timestr.push(line[i]);
		}
		var momentDate = Date(timestr.join(':'));
		return momentDate;
	}
	
	var getCertAttributes = function(certificate) {
		var outattrs = {};
		var attrs = certificate.split('\n');
		for(var i = 0; i <= attrs.length - 1; i++) {
			let data = attrs[i].split(':');
			let attr = data[0].trim(' ');
			if(attr=='Public Key Algorithm') {
				outattrs[attr] = data[1].trim(' ');
			} else if(attr=='Signature Algorithm') {
				outattrs[attr] = data[1].trim(' ');
			} else if(attr=='Serial Number') {
				outattrs[attr] = attrs[i+1].trim(' ');
			} else if(attr.indexOf('Public-Key') >= 0) {
				outattrs['Public-Key'] = data[1].trim(' ').split(' ')[0].substring(1);
			} else if(attr=='Not After') {
				let parse = data.splice(1);
				var date = parse.join(':').replace('\r\n','').replace('\r','').trim(' ');
				//outattrs[attr] = convertTime(date);
				outattrs[attr] = new Date(date);
			} else if(attr=='Not Before') {
				let parse = data.splice(1);
				var date = parse.join(':').replace('\r\n','').replace('\r','').trim(' ');
				//console.log(new Date(date));
				//outattrs[attr] = convertTime(date);
				outattrs[attr] = new Date(date);
			}
		}
		var lastline = attrs[attrs.length - 2];
		if(lastline.indexOf('Fingerprint')) {
			outattrs['Thumbprint'] = lastline.split('=')[1].replace('\r\n','').replace('\r','').trim(' ');
		}
		return outattrs;
	}
	
	var getCertInfo = function(cert, callback) {
		var cmd = [];
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				cmd.push('x509 -in ' + path + ' -text -noout -fingerprint');
				runOpenSSLCommand(cmd.join(), function(err, out) {
					//console.log(out);
					if(err) {
						callback(true,out.stderr,cmd.join());
					} else {
						var extensions = getx509v3Attributes(out.stdout);
						var subject = getSubject(out.stdout);
						var attrs = getCertAttributes(out.stdout);
						var csroptions = {
							extensions: extensions,
							subject: subject,
							attributes: attrs
						}
						//callback(false,out.stdout,cmd.join());
						callback(false,csroptions,'openssl ' + cmd.join().replace(path, 'cert.crt'));
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	this.getOpenSSLCertInfo = function(cert, callback) {
		var cmd = [];
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				cmd.push('x509 -in ' + path + ' -text -noout -fingerprint');
				runOpenSSLCommand(cmd.join(), function(err, out) {
					//console.log(out);
					if(err) {
						callback(true,out.stderr,cmd.join());
					} else {
						callback(false,out.stdout,'openssl ' + cmd.join().replace(path, 'cert.crt'));
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	this.getCertInfo = function(cert, callback) {
		getCertInfo(cert, callback);
	}
	
	this.convertCertToCSR = function(cert, callback) {
		var cmd = [];
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
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
					cleanupCallback1();
				});
			});
		});
	}
	
	this.getOCSPHashes = function(ca, cert, hashalg, callback) {
		let hashes = ['sha1', 'sha256', 'sha384', 'sha512'];
		//console.log(hashes.includes(hashalg))
		if(hashes.includes(hashalg)) {
			//ok
		} else {
			callback('invalid hash specified',false, false);
		}
		var cmd = [];
		tmp.file(function _tempFileCreated(err, certpath, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(certpath, cert, function() {
				tmp.file(function _tempFileCreated(err, capath, fd, cleanupCallback2) {
					if (err) throw err;
					fs.writeFile(capath, ca, function() {
						cmd.push('ocsp -issuer ' + capath + ' -' + hashalg + ' -cert ' + certpath + ' -req_text');
						runOpenSSLCommand(cmd.join(), function(err, out) {
							if(err) {
								callback(true,out.stderr,cmd.join());
							} else {
								//console.log(out.stdout);
								let lines = out.stdout.split('\n');
								let ocspparams = {};
								for(let i = 0; i <= lines.length - 1; i++) {
									let line = lines[i].split(': ')
									//console.log(line[0])
									if(line[0].trim(' ') == 'Hash Algorithm') {
										ocspparams[line[0].trim(' ')] = line[1].replace('\r','');
									} else if(line[0].trim(' ') == 'Issuer Name Hash') {
										if(line[1].indexOf('\\') >= 1) {
											ocspparams[line[0].trim(' ')] = line[1].replace('\\','').replace('\r','') + lines[i + 1].replace('\r','');
										} else {
											ocspparams[line[0].trim(' ')] = line[1].replace('\r','');
										}
									} else if(line[0].trim(' ') == 'Issuer Key Hash') {
										if(line[1].indexOf('\\') >= 1) {
											ocspparams[line[0].trim(' ')] = line[1].replace('\\','').replace('\r','') + lines[i + 1].replace('\r','');
										} else {
											ocspparams[line[0].trim(' ')] = line[1].replace('\r','');
										}
									} else if(line[0].trim(' ') == 'Serial Number') {
										if(line[1].indexOf('\\') >= 1) {
											ocspparams[line[0].trim(' ')] = line[1].replace('\\','').replace('\r','') + lines[i + 1].replace('\r','');
										} else {
											ocspparams[line[0].trim(' ')] = line[1].replace('\r','');
										}
									} else {
										
									}
								}
								callback(false, ocspparams, 'openssl ' + cmd.join().replace(certpath, 'cert.crt').replace(capath, 'ca.crt'));
							}
							cleanupCallback1();
							cleanupCallback2();
						});
					});
				});
			});
		});
	}
	
	var importRSAPrivateKey = function(key, password, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var pass = '_PLAIN_'; //Just pass a bogus password to complete the command properly. It will not be used for unencrypted keys and helps prevent circumstances when certain versions of openssl will prompt for a password when none is provided
				var passcmd = '-passin pass:' + pass;
				if(password) {
					var passfile = tmp.fileSync();
					fs.writeFileSync(passfile.name, password);
					passcmd = '-passin file:' + passfile.name;
				}
				var cmd = ['rsa ' + passcmd + ' -in ' + path];
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					if(err) {
						cmd.push('-inform DER');
						runOpenSSLCommand(cmd.join(' '), function(err, out) {
							if(err) {
								if(!password) {
									pass = '';
									passcmd = '-passin pass:' + pass;
                                }
								cmd = ['pkcs12 ' + passcmd + ' -in ' + path + ' -nocerts -nodes'];
								runOpenSSLCommand(cmd.join(' '), function(err, out) {
									if(err) {
										if(password) {
											passfile.removeCallback();
										}
										cleanupCallback1();
										callback(out.stderr,false);
										//console.log(out);
									} else {
										convertToPKCS8(out.stdout, false, function(err, key) {
											if(password) {
												passfile.removeCallback();
											}
											cleanupCallback1();
											callback(false,key.data);
										});
									}
								});
							} else {
								convertToPKCS8(out.stdout, false, function(err, key) {
									if(password) {
										passfile.removeCallback();
									}
									cleanupCallback1();
									callback(false,key.data);
								});
							}
						});
					} else {
						convertToPKCS8(out.stdout, false, function(err, key) {
							if(password) {
								passfile.removeCallback();
							}
							cleanupCallback1();
							callback(false,key.data);
						});
					}
					//cleanupCallback1();
				});
			});
		});
	}
	
	var importECCPrivateKey = function(key, password, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var pass = '_PLAIN_'; //Just pass a bogus password to complete the command properly. It will not be used for unencrypted keys and helps prevent circumstances when certain versions of openssl will prompt for a password when none is provided
				var passcmd = '-passin pass:' + pass;
				if(password) {
					var passfile = tmp.fileSync();
					fs.writeFileSync(passfile.name, password);
					passcmd = '-passin file:' + passfile.name;
				}
				var cmd = ['ec ' + passcmd + ' -in ' + path];
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					if(err) {
						cmd.push('-inform DER');
						runOpenSSLCommand(cmd.join(' '), function(err, out) {
							if(err) {
								if(!password) {
									pass = '';
									passcmd = '-passin pass:' + pass;
                                }
								cmd = ['pkcs12 ' + passcmd + ' -in ' + path + ' -nocerts -nodes'];
								runOpenSSLCommand(cmd.join(' '), function(err, out) {
									if(err) {
										if(password) {
											passfile.removeCallback();
										}
										cleanupCallback1();
										callback(out.stderr,false);
										//console.log(out);
									} else {
										convertToPKCS8(out.stdout, false, function(err, key) {
											if(password) {
												passfile.removeCallback();
											}
											cleanupCallback1();
											callback(false,key.data);
										});
									}
								});
							} else {
								convertToPKCS8(out.stdout, false, function(err, key) {
									if(password) {
										passfile.removeCallback();
									}
									cleanupCallback1();
									callback(false,key.data);
								});
							}
						});
					} else {
						convertToPKCS8(out.stdout, false, function(err, key) {
							if(password) {
								passfile.removeCallback();
							}
							cleanupCallback1();
							callback(false,key.data);
						});
					}
					//cleanupCallback1();
				});
			});
		});
	}
	
	this.importRSAPrivateKey = function(key, password, callback) {
		importRSAPrivateKey(key, password, callback);
	}
	
	this.importECCPrivateKey = function(key, password, callback) {
		importECCPrivateKey(key, password, callback);
	}
	
	this.convertPEMtoDER = function(cert, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				tmp.file(function _tempFileCreated(err, derpath, fd, cleanupCallback2) {
					var cmd = ['x509 -inform PEM -outform DER -in ' + path + ' -out ' + derpath];
					runOpenSSLCommand(cmd.join(' '), function(err, out) {
						if(err) {
							callback(true, false, out.command.replace(path, 'cert.pem').replace(derpath, 'cert.cer'));
							cleanupCallback2();
						} else {
							fs.readFile(derpath, function(err, data) {
								callback(false, data, out.command.replace(path, 'cert.pem').replace(derpath, 'cert.cer'));
								cleanupCallback2();
							});
						}
						cleanupCallback1();
					});
				});
			});
		});
	}
	
	var convertDERtoPEM = function(cert, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				var cmd = ['x509 -inform DER -outform PEM -in ' + path];
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					if(err) {
						callback(true, false, out.command.replace(path, 'cert.pem'));
					} else {
						callback(false, out.stdout, out.command.replace(path, 'cert.pem'));
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	this.convertDERtoPEM = function(cert, callback) {
		convertDERtoPEM(cert, callback);
	}
	
	this.downloadIssuer = function(uri, callback) {
		if(uri.indexOf('https://') >= 0) {
			https.get(uri, (resp) => {
				let data = [];

				// A chunk of data has been recieved.
				resp.on('data', (chunk) => {
					data.push(chunk);
				});

				// The whole response has been received. Print out the result.
				resp.on('end', () => {
					if(data.toString().indexOf('BEGIN CERTIFICATE') >= 0) {
						callback(false, Buffer.concat(data).toString());
					} else {
						convertDERtoPEM(Buffer.concat(data), function(err, cert, cmd) {
							callback(false, cert);
						});
					}
				});

			}).on("error", (err) => {
				callback(true, false);
			});
		} else {
			http.get(uri, (resp) => {
				let data = [];

				// A chunk of data has been recieved.
				resp.on('data', (chunk) => {
					data.push(chunk);
				});

				// The whole response has been received. Print out the result.
				resp.on('end', () => {
					if(data.toString().indexOf('BEGIN CERTIFICATE') >= 0) {
						callback(false, Buffer.concat(data).toString());
					} else {
						convertDERtoPEM(Buffer.concat(data), function(err, cert, cmd) {
							callback(false, cert);
						});
					}
				});

			}).on("error", (err) => {
				callback(true, false);
			});
		}
	}
	
	this.getIssuerURI = function(cert, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				var cmd = ['x509 -noout -in ' + path + ' -text'];
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					let uri = false;
					if(err) {
						callback(true, false, out.command.replace(path, 'cert.pem'));
					} else {
						let output = out.stdout.split('\n');
						for(let i = 0; i <= output.length - 1; i++) {
							if(output[i].indexOf('CA Issuers') >= 0) {
								let normalized = output[i].split('URI:')[1].replace('\r\n','').replace('\r','');
								if(normalized.indexOf('http') >= 0) {
									uri = normalized;
									break;
								}
							}
						}
						callback(false, uri, out.command.replace(path, 'cert.pem'));
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	this.getOCSPURI = function(cert, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				var cmd = ['x509 -noout -in ' + path + ' -ocsp_uri'];
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					var uri = out.stdout.replace('\r\n','').replace('\n','')
					if(err || uri == '') {
						callback('Cannot get OCSP URI from certificate.', false, out.command.replace(path, 'cert.pem'), out.command.replace(path, 'cert.pem'));
					} else {
						callback(false, uri, out.command.replace(path, 'cert.pem'));
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	this.queryOCSPServer = function(cacert, cert, uri, hash, nonce, callback) {
		//console.log(cert);
		//console.log(cacert);
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				tmp.file(function _tempFileCreated(err, ca, fd, cleanupCallback2) {
					if (err) throw err;
					fs.writeFile(ca, cacert, function() {
						var cmd = ['ocsp -'+ hash +' -issuer '+ ca +' -cert ' + path + ' -header host=' + uri.split('/')[2] + ' -url ' + uri + ' -text -CAfile ' + ca];
						if(!nonce) {
							cmd.push('-no_nonce');
						}
						runOpenSSLCommand(cmd.join(' '), function(err, out) {
							//console.log(cmd);
							if(err) {
								getCertInfo(cert, function(err, certinfo, cmd) {
									if(err) {
										//error
									} else {
										certinfo.base64 = cert;
										callback(out.stderr, out.stdout.replace(path, 'cert.pem'), {
											command: out.command.replace(path, 'cert.pem').replace(ca, 'ca.pem').replace(ca, 'ca.pem'),
											ca: cacert,
											cert: certinfo,
											uri: uri
										});
									}
								});
								
								
								
								/*callback(out.stderr, out.stderr, {
									command: out.command.replace(path, 'cert.pem').replace(ca, 'ca.pem'),
                                                                        ca: cacert,
                                                                        cert: cert
                                                                });*/
							} else {
								//let output = out.stdout.replace(path + ': ','').split('\n');
								//console.log(output);
								//let status = output[0].replace('\r','');
								//let thisupdate = new Date(output[1].split('pdate: ')[1]);
								//let nextupdate = new Date(output[2].split('pdate: ')[1]);
								getCertInfo(cert, function(err, certinfo, cmd) {
									if(err) {
										//error
									} else {
										certinfo.base64 = cert;
										callback(false, out.stdout.replace(path, 'cert.pem'), {
											command: out.command.replace(path, 'cert.pem').replace(ca, 'ca.pem').replace(ca, 'ca.pem'),
											ca: cacert,
											cert: certinfo,
											uri: uri
										});
									}
								});
							}
							cleanupCallback1();
							cleanupCallback2();
						});
					});
				});
			});
		});
	}
	
	var convertToPKCS1 = function(key, encryption, callback) {
		//console.log(key);
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var cmd = ['rsa -in ' + path];
				if(encryption) {
					//var passfile = tmp.fileSync();
					//fs.writeFileSync(passfile.name, encryption.password);
					var passfile = tmp.fileSync();
                                        fs.writeFileSync(passfile.name, encryption.password);
                                        var passout = tmp.fileSync();
                                        fs.writeFileSync(passout.name, encryption.password);
					//console.log(encryption);
					cmd.push('-' + encryption.cipher + ' -passin file:' + passfile.name + ' -passout file:' + passout.name);// + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
				}
				//console.log(cmd);
				
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					//console.log(out);
					if(err) {
						callback(err,{
							command: out.command.replace(path, 'priv.key'),
							data: out.stdout
						});
					} else {
						callback(false,{
							command: out.command.replace(path, 'priv.key'),
							data: out.stdout
						});
					}
					if(encryption) {
						passfile.removeCallback();
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	var convertToPKCS8 = function(key, password, callback) {
		//console.log(key);
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var cmd = ['pkcs8 -topk8 -inform PEM -outform PEM -in ' + path];
				if(password) {
					var passfile = tmp.fileSync();
					fs.writeFileSync(passfile.name, password);
					cmd.push('-nocrypt -passin file:' + passfile.name);// + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
				} else {
					cmd.push('-nocrypt');
				}
				//console.log(cmd);
				
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					if(err) {
						callback(err,{
							command: out.command.replace(path, 'priv.key'),
							data: out.stdout
						});
					} else {
						callback(false,{
							command: out.command.replace(path, 'priv.key'),
							data: out.stdout
						});
					}
					if(password) {
						passfile.removeCallback();
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	var convertToPKCS8Encrypt = function(key, password, callback) {
		//console.log(key);
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, key, function() {
				var cmd = ['pkcs8 -topk8 -inform PEM -outform PEM -in ' + path];
				if(password) {
					var passfile = tmp.fileSync();
					fs.writeFileSync(passfile.name, password);
					var passout = tmp.fileSync();
					fs.writeFileSync(passout.name, password);
					cmd.push('-passin file:' + passfile.name + ' -passout file:' + passout.name);// + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
				} else {
					cmd.push('-nocrypt');
				}
				//console.log(cmd);
				
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					if(err) {
						callback(err,{
							command: out.command.replace(path, 'priv.key'),
							data: out.stdout
						});
					} else {
						callback(false,{
							command: out.command.replace(path, 'priv.key'),
							data: out.stdout
						});
					}
					if(password) {
						passfile.removeCallback();
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	this.generateConfig = function(options, cert, persistentca, callback) {
		generateConfig(options, cert, persistentca, callback);
	}
	
	var generateConfig = function(options, cert, persistentca, callback) {
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
		
		const validtlsfeature = [
			'status_request'
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
			'ipsecIKE',
			'ipsecEndSystem',
			'ipsecTunnel',
			'ipsecUser'
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
			'emailAddress',
			'jurisdictionOfIncorporationCountryName',
			'jurisdictionOfIncorporationStateOrProvinceName',
			'jurisdictionLocalityName',
			'businessCategory',
			'serialNumber'
		];
		const validsantypes = [
			'DNS',
			'IP',
			'URI',
			'email',
			'RID',
			'dirName',
			'otherName'
		];
		var req = [];
		
		if(persistentca) {
			req.push('[ ca ]');
			req.push('default_ca = CA_default');
			req.push('[ CA_default ]');
			req.push('base_dir = .');
			req.push('certificate = $base_dir/ca.crt');
			req.push('private_key = $base_dir/ca.key');
			req.push('new_certs_dir = $base_dir/certs ');
			req.push('database = $base_dir/index.txt');
			req.push('serial = $base_dir/serial.txt');
			req.push('unique_subject = no');
			req.push('default_days = 365');
			req.push('default_crl_days = 1');	
			req.push('default_md = ' + options.hash);
			req.push('preserve = yes');
			req.push('x509_extensions = req_ext');
			req.push('email_in_dn = no');
			req.push('[ signing_policy ]');
			req.push('countryName = optional');
			req.push('stateOrProvinceName = optional');
			req.push('localityName = optional');
			req.push('organizationName = optional');
			req.push('organizationalUnitName = optional');
			req.push('commonName = optional');
			req.push('emailAddress = optional');
		}
		
		req.push('[ req ]');
		req.push('default_md = ' + options.hash);
		req.push('prompt = no');
		if(cert || options.extensions) {
			req.push('req_extensions = req_ext');
		}
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
		/*if(options.mustStaple) {
			if(options.mustStaple==true) {
				req.push('1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05');
			}
		}*/
		if(cert) {
			req.push('subjectKeyIdentifier = hash');
			req.push('authorityKeyIdentifier = keyid:always,issuer');
		}
		if(options.extensions) {
			//req.push('[ req_ext ]');
			var endconfig = [];
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
							callback('Invalid ' + ext + ' type : ' +  '"' + type + '"', false);
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
				} else if (ext == 'tlsfeature') {
					var critical = '';
					var valid = 0;
					for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
						//console.log(options.extensions[ext]);
						if(validtlsfeature.indexOf(options.extensions[ext][i]) < 0) {
							callback('Invalid ' + ext + ': ' + options.extensions[ext][i], false);
							return false;
						} else {
							valid++;
						}
					}
					if(valid > 0) {
						//if(options.extensions[ext].critical) critical = 'critical,';
						req.push(ext + '=' + options.extensions[ext].join(','));
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
				} else if (ext == 'authorityInfoAccess') {
					let aiaconfig = [];
					if(options.extensions[ext]['caIssuers']) {
						for(var i = 0; i <= options.extensions[ext]['caIssuers'].length - 1; i++) {
							aiaconfig.push('caIssuers;URI.' + i + ' = ' + options.extensions[ext]['caIssuers'][i]);
						}
					}
					if(options.extensions[ext]['OCSP']) {
						for(var i = 0; i <= options.extensions[ext]['OCSP'].length - 1; i++) {
							aiaconfig.push('OCSP;URI.' + i + ' = ' + options.extensions[ext]['OCSP'][i]);
						}
					}
					if(aiaconfig.length > 0) {
						req.push('authorityInfoAccess = @issuer_info');
						endconfig.push('[ issuer_info ]');
						for(var i = 0; i <= aiaconfig.length - 1; i++) {
							endconfig.push(aiaconfig[i]);
						}
					}
				} else if (ext == 'crlDistributionPoints') {
					if(options.extensions[ext].length > 0) {
						req.push('crlDistributionPoints = @crl_info');
						endconfig.push('[ crl_info ]');
						for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
							endconfig.push('URI.' + i + ' = ' + options.extensions[ext][i]);
						}
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
			if(endconfig.length > 0) {
				for(var i = 0; i <= endconfig.length - 1; i++) {
					req.push(endconfig[i]);
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
		tmp.file(function _tempFileCreated(err, pfxpath, fd, cleanupCallback1) {
			if (err) throw err;
			var cmd = ['pkcs12 -export -out ' + pfxpath + ' -inkey ' + keypath + ' -in ' + certpath];
			if(passout) {
				var passoutfile = tmp.fileSync();
				fs.writeFileSync(passoutfile.name, passout);
				cmd.push('-passout file:' + passoutfile.name);
			} else {
				cmd.push('-nodes -passout pass:');
			}
			if(passin) {
				var passinfile = tmp.fileSync();
				fs.writeFileSync(passinfile.name, passin);
				cmd.push('-passin file:' + passinfile.name);
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
						command: [out.command.replace(keypath, 'priv.key').replace(certpath, 'cert.crt').replace(pfxpath, 'cert.pfx').replace(capath, 'ca.crt') + ' -out cert.pfx']
					});
					cleanupCallback1();
				} else {
					fs.readFile(pfxpath, function(err, data) {
						//console.log(out.command);
						callback(false, data, {
							command: [out.command.replace(keypath, 'priv.key').replace(certpath, 'cert.crt').replace(pfxpath, 'cert.pfx').replace(capath, 'ca.crt') + ' -out cert.pfx']
						});
						cleanupCallback1();
					});
				}if(passout) {
					passoutfile.removeCallback();
				}
				if(passin) {
					passinfile.removeCallback();
				}
			});
		});
	}
	
	this.createPKCS12 = function(cert, key, passin, passout, ca, callback) {
		tmp.file(function _tempFileCreated(err, certpath, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(certpath, cert, function() {
				tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback2) {
					if (err) throw err;
					fs.writeFile(keypath, key, function() {
						if(ca) {
							tmp.file(function _tempFileCreated(err, capath, fd, cleanupCallback3) {
								if (err) throw err;
								fs.writeFile(capath, ca, function() {
									generatePKCS12(certpath, keypath, passin, passout, capath, function(err, pfx, command) {
										callback(err, pfx, command);
										cleanupCallback1();
										cleanupCallback2();
										cleanupCallback3();
									});
								});
							});
						} else {
							generatePKCS12(certpath, keypath, passin, passout, false, function(err, pfx, command) {
								callback(err, pfx, command);
								cleanupCallback1();
								cleanupCallback2();
							});
						}
					});
				});
			});
		});
	}
	
	this.CASignCSR = function(csr, options, persistcapath, ca, key, password, callback) {
		//console.log(csr);
		options.days = typeof options.days !== 'undefined' ? options.days : 365;
		if(persistcapath) {
			generateConfig(options, true, persistcapath, function(err, req) {
				if(err) {
					callback(err,{
						command: null,
						data: null
					});
					return false;
				} else {
					tmp.file(function _tempFileCreated(err, config, fd, cleanupCallback1) {
						if (err) throw err;
						//correct ca path
						var careq = [];
						for(var i = 0; i<= req.length - 1; i++) {
							if(req[i]=='base_dir = .') {
								careq.push('base_dir = "' + persistcapath + '"');
							} else {
								careq.push(req[i]);
							}
						}
						fs.writeFile(config, careq.join('\r\n'), function() {
							tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback2) {
								if (err) throw err;
								fs.writeFile(csrpath, csr, function() {
									var cmd = ['ca -config ' + config + ' -create_serial -in ' + csrpath + ' -policy signing_policy -batch -notext'];
									if(options.startdate) {
										cmd.push('-startdate ' + moment(options.startdate).format('YYYYMMDDHHmmss') + 'Z -enddate ' + moment(options.enddate).format('YYYYMMDDHHmmss') + 'Z');
									} else {
										cmd.push('-days ' + options.days);
									}
									if(password) {
										var passfile = tmp.fileSync();
										fs.writeFileSync(passfile.name, password);
										cmd.push('-passin file:' + passfile.name);
									}
									runOpenSSLCommand(cmd.join(' '), function(err, out) {
										if(err) {
											callback(err, out.stdout, {
												command: [out.command.replace(config, 'config.txt').replace(csrpath, 'cert.csr')],
												files: {
													config: req.join('\r\n')
												}
											});
										} else {
											fs.readFile(persistcapath + '/serial.txt', function(err, serial) {
												callback(false, out.stdout, {
													command: [out.command.replace(config, 'config.txt').replace(csrpath, 'cert.csr')],
													serial: serial.toString().replace('\r\n', '').replace('\n', ''),
													files: {
														config: req.join('\r\n')
													}
												});
											});
										}
										if(password) {
											passfile.removeCallback();
										}
										cleanupCallback1();
										cleanupCallback2();
									});
								});
							});
						});
					});
				}
			});
		} else {
			generateConfig(options, true, false, function(err, req) {
				if(err) {
					callback(err,{
						command: null,
						data: null
					});
					return false;
				} else {
					tmp.file(function _tempFileCreated(err, capath, fd, cleanupCallback1) {
						if (err) throw err;
						fs.writeFile(capath, ca, function() {
							tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback2) {
								if (err) throw err;
								fs.writeFile(csrpath, csr, function() {
									tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback3) {
										if (err) throw err;
										fs.writeFile(keypath, key, function() {
											tmp.file(function _tempFileCreated(err, csrconfig, fd, cleanupCallback4) {
												if (err) throw err;
												fs.writeFile(csrconfig, req.join('\r\n'), function() {
													tmp.tmpName(function _tempNameGenerated(err, serialpath) {
														if (err) throw err;
														//fs.writeFile(serialpath, req.join('\r\n'), function() {
															var cmd = ['x509 -req -in ' + csrpath + ' -days ' + options.days + ' -CA ' + capath + ' -CAkey ' + keypath + ' -extfile ' + csrconfig + ' -extensions req_ext -CAserial ' + serialpath + ' -CAcreateserial'];
															//var cmd = ['x509 -req -in ' + csrpath + ' -days ' + options.days + ' -CA ' + capath + ' -CAkey ' + keypath + ' -extfile ' + csrconfig + ' -extensions req_ext'];
															if(password) {
																var passfile = tmp.fileSync();
																fs.writeFileSync(passfile.name, password);
																cmd.push('-passin file:' + passfile.name);
															}
													
													//console.log(cmd);
													
															runOpenSSLCommand(cmd.join(' '), function(err, out) {
																if(err) {
																	callback(err, out.stdout, {
																		command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'cert.csr').replace(capath, 'ca.crt').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
																		files: {
																			config: req.join('\r\n')
																		}
																	});
																} else {
																	fs.readFile(serialpath, function(err, serial) {
																		callback(false, out.stdout, {
																			command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'cert.csr').replace(capath, 'ca.crt').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
																			serial: serial.toString().replace('\r\n', '').replace('\n', ''),
																			files: {
																				config: req.join('\r\n')
																			}
																		});
																	});
																}
																fs.unlink(serialpath, function(err) {
																	//delete temp serial file
																});
																if(password) {
																	passfile.removeCallback();
																}
																cleanupCallback1();
																cleanupCallback2();
																cleanupCallback3();
																cleanupCallback4();
																//cleanupCallback5();
															//});
														});
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
	}
	
	this.selfSignCSR = function(csr, options, key, password, callback) {
		//console.log(csr);
		options.days = typeof options.days !== 'undefined' ? options.days : 365;
		generateConfig(options, true, false, function(err, req) {
			if(err) {
				callback(err,{
					command: null,
					data: null
				});
				return false;
			} else {
				tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback1) {
					if (err) throw err;
					fs.writeFile(csrpath, csr, function() {
						tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback2) {
							if (err) throw err;
							fs.writeFile(keypath, key, function() {
								tmp.file(function _tempFileCreated(err, csrconfig, fd, cleanupCallback3) {
									if (err) throw err;
									fs.writeFile(csrconfig, req.join('\r\n'), function() {
										var cmd = ['req -x509 -nodes -in ' + csrpath + ' -days ' + options.days + ' -key ' + keypath + ' -config ' + csrconfig + ' -extensions req_ext'];
										if(password) {
											var passfile = tmp.fileSync();
											fs.writeFileSync(passfile.name, password);
											cmd.push('-passin file:' + passfile.name);
										}
								
								//console.log(cmd);
								
										runOpenSSLCommand(cmd.join(' '), function(err, out) {
											if(err) {
												callback(err, out.stdout, {
													command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'cert.csr').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
													files: {
														config: req.join('\r\n')
													}
												});
											} else {
												callback(false, out.stdout, {
													command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'cert.csr').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
													files: {
														config: req.join('\r\n')
													}
												});
											}
											if(password) {
												passfile.removeCallback();
											}
											cleanupCallback1();
											cleanupCallback2();
											cleanupCallback3();
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
		generateConfig(options, false, false, function(err, req) {
			if(err) {
				callback(err,{
					command: null,
					data: null
				});
				return false;
			} else {
				tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback1) {
					if (err) throw err;
					fs.writeFile(keypath, key, function() {
						tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback2) {
							if (err) throw err;
							fs.writeFile(csrpath, req.join('\r\n'), function() {
								var cmd = ['req -new -nodes -key ' + keypath + ' -config ' + csrpath];
								if(password) {
									var passfile = tmp.fileSync();
									fs.writeFileSync(passfile.name, password);
									cmd.push('-passin file:' + passfile.name);
								}
						
						//console.log(cmd);
						
								runOpenSSLCommand(cmd.join(' '), function(err, out) {
									if(err) {
										callback(err, out.stdout, {
											command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'csrconfig.txt') + ' -out cert.csr'],
											files: {
												config: req.join('\r\n')
											}
										});
									} else {
										callback(false, out.stdout, {
											command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'csrconfig.txt') + ' -out cert.csr'],
											files: {
												config: req.join('\r\n')
											}
										});
									}
									if(password) {
										passfile.removeCallback();
									}
									cleanupCallback1();
									cleanupCallback2();
								});
							});
						});
					});
				});
			}
		});
	}
	
	this.getAvailableCurves = function(callback) {
		let cmd = ['ecparam -list_curves'];
		runOpenSSLCommand(cmd.join(' '), function(err, out) {
			if(err) {
				callback(err, false, null);
			} else {
				let lines = out.stdout.split('\n');
				let curves = Array();
				//last line of output was blank on current version of openssl
				for(let i = 0; i <= lines.length - 2; i++) {
					if(lines[i].indexOf(':') >= 0) {
						let curve = {};
						let line = lines[i].split(':');
						curve['curve'] = line[0].trim(' ');
						if(line[1].trim(' ')!='') {
							curve['description'] = line[1].trim(' ');
						} else {
							curve['description'] = lines[i + 1].replace('\t','').replace('\r','');
						}
						curves.push(curve);
					}
				}
				callback(false, curves, [out.command]);
			}
		});
	}
	
	this.generateECCPrivateKey = function(options, callback) {
		let cmd = ['ecparam -name '+ options.curve +' -param_enc named_curve -genkey -noout']
		runOpenSSLCommand(cmd.join(' '), function(err, out) {
			let firstcmd = out;
			if(err) {
				callback(err, false, null);
			} else {
				if(options.encryption) {
					tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
						if (err) throw err;
						fs.writeFile(path, out.stdout, function() {
							var passoutfile = tmp.fileSync();
							fs.writeFileSync(passoutfile.name, options.encryption.password);
							let cmd = ['ec -in '+ path +' -'+ options.encryption.cipher +' -passout file:' + passoutfile.name];
							runOpenSSLCommand(cmd.join(' '), function(err, out) {
								let secondcmd = out;
								cleanupCallback1();
								if(options.format=="PKCS8") {
									convertToPKCS8Encrypt(out.stdout, options.encryption.password, function(err, key) {
										callback(false,key.data,[firstcmd.command, secondcmd.command.replace(path, 'priv.key').replace('file:'+passoutfile.name,'pass:yourpassword'),out.command]);
									});
								} else {
									callback(false, out.stdout, [firstcmd.command, out.command.replace(path, 'priv.key').replace('file:'+passoutfile.name,'pass:yourpassword')]);
								}
							});
						});
					});
				} else {
					if(options.format=="PKCS8") {
						convertToPKCS8(out.stdout, false, function(err, key) {
							callback(false,key.data,[out.command, key.command]);
						});
					} else {
						callback(false, out.stdout, [out.command + ' -out priv.key']);
					}
				}
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
					var passfile = tmp.fileSync();
					fs.writeFileSync(passfile.name, options[option].password);
					cmd.push('-pass file:' + passfile.name + ' -' + options[option].cipher);
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
				if(option=='encryption' && options[option]) {
					passfile.removeCallback();
				}
				callback(false, out.stdout, [out.command + ' -out priv.key']);
			});
		} else if (options.format == 'PKCS1' ) {
			runOpenSSLCommand(cmd.join(' '), function(err, outkey) {
				if(option=='encryption' && options[option]) {
					passfile.removeCallback();
				}
				if(err) {
					callback(err, false);
				} else {
					convertToPKCS1(outkey.stdout, options.encryption, function(err, out) {
						if(err) {
							callback(err, false);
						} else {
							callback(false, out.data, [ outkey.command + ' -out priv.key', out.command + ' -out priv.key' ]);
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
