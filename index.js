'use strict';
const { spawn } = require( 'child_process' );
const https = require('https');
const http = require('http');
var tmp = require('tmp');
var fs = require('fs');
var opensslbinpath = 'openssl'; //use full path if not in system PATH
var pkcs11toolbinpath = 'pkcs11-tool'; //use full path if not in system PATH
const tempdir = '/tmp/';
var moment = require('moment');
var net = require('net');
var crypto = require('crypto');

var openssl = function(options) {
	
	if(options) {
		if(options.binpath) {
			opensslbinpath = options.binpath;
		} else {
			
		}
		if(options.pkcs11toolbinpath) {
			pkcs11toolbinpath = options.pkcs11toolbinpath;
		} else {
			
		}
	} else {
		
	}
	
	var normalizeCommand = function(command) {
		let cmd = command.split(' ');
		let outcmd = [];
		let cmdbuffer = [];
		for(let i = 0; i <= cmd.length - 1; i++) {
			if(cmd[i].charAt(cmd[i].length - 1) == '\\') {
				cmdbuffer.push(cmd[i]);
			} else {
				if(cmdbuffer.length > 0) {
					outcmd.push(cmdbuffer.join(' ') + ' ' + cmd[i]);
					cmdbuffer.length = 0;
				} else {
					outcmd.push(cmd[i]);
				}
			}
		}
		return outcmd;
	}

	var runPKCS11ToolCommand = function(cmd, callback) {
		const stdoutbuff = [];
		const stderrbuff = [];
		var terminate = false;
		
		if(cmd.indexOf('s_client') >= 0) {
			terminate = true;
		}
		
		const pkcs11tool = spawn( pkcs11toolbinpath, normalizeCommand(cmd) );
		
		pkcs11tool.stdout.on('data', function(data) {
			stdoutbuff.push(data.toString());
			/*//pkcs11tool.stdin.setEncoding('utf-8');
			setTimeout(function() {
				//pkcs11tool.stdin.write("QUIT\r");
				//console.log('QUIT\r\n');
				//pkcs11tool.stdin.end();
				pkcs11tool.kill();
			}, 1000);*/
			if(terminate) {
				//if(data.toString().indexOf('Verify return code: 0 (ok)') >= 0 ) {
				if(stdoutbuff.join('').toString().indexOf('Verify return code: ') >= 0 ) {
					pkcs11tool.kill();
				}
			}
		});

		/*pkcs11tool.stdout.on('end', function(data) {
			stderrbuff.push(data.toString());
		});*/
		
		pkcs11tool.stderr.on('data', function(data) {
			stderrbuff.push(data.toString());
		});
		
		pkcs11tool.on('exit', function(code) {
			if(terminate && code==null) {
				code = 0;
			}
			var out = {
				command: 'pkcs11-tool ' + cmd,
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

	var runOpenSSLCommandv2 = function(params, callback) {
		const stdoutbuff = [];
		const stderrbuff = [];
		var terminate = false;
		
		if(params.cmd.indexOf('s_client') >= 0) {
			terminate = true;
		}
		
		const openssl = spawn( opensslbinpath, normalizeCommand(params.cmd) );

		if(params.hasOwnProperty('stdin')) {
			if(params.stdin) {
				openssl.stdin.write(params.stdin);
				openssl.stdin.end();
			}
		}
		
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
				command: 'openssl ' + params.cmd,
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
	
	var runOpenSSLCommand = function(cmd, callback) {
		const stdoutbuff = [];
		const stderrbuff = [];
		var terminate = false;
		
		if(cmd.indexOf('s_client') >= 0) {
			terminate = true;
		}
		
		const openssl = spawn( opensslbinpath, normalizeCommand(cmd) );
		
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
	
	var getSubjectAlternativeNames = function(sans, originalcert, callback) {
		var names = {}
		let processedunsupportedtypes = false;
		var sanarr = sans.content[0].split(', ');
		for(var i = 0; i <= sanarr.length - 1; i++) {
			var san = sanarr[i].split(':');
			var type;
			if(san[0]=='IP Address') {
				type = 'IP';
			} else if(san[0]=='Registered ID') {
				type = 'RID';
			} else {
				type = san[0];
			}
			var value = san[1];
			//console.log(type + ' - ' + value);
			if(value!='<unsupported>') {
				if(names[type]) {
					names[type].push(value);
				} else {
					names[type] = [value];
				}
			} else {
				if(!processedunsupportedtypes) {
					processedunsupportedtypes = true;
				}
			}
		}
		
		if(processedunsupportedtypes) {
			getUnsupportedSANs(originalcert, function(err, otherNames) {
				if(err) {
					return false;
				} else {
					names['otherName'] = otherNames;
					/*if(Object.keys(names).length > 0) {
						return names;
					} else {
						return false;
					}*/
					//console.log(names);
					callback(null, names);
				}
			});
		} else {
			/*if(Object.keys(names).length > 0) {
				return names;
			} else {
				return false;
			}*/
			//console.log(names);
			callback(null, names);
		}
	}
	
	var getUnsupportedSANs = function(cert, callback) {
		let oids = {
			"Microsoft Universal Principal Name": "msUPN",
			"Microsoft Smartcardlogin": "msSmartcardLogin"
		}
		let otherNameSANs = [];
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				let cmd = ['asn1parse -in ' + path + ' -inform pem'];
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					//cleanupCallback1();
					if(err) {
						//console.log(err);
						cleanupCallback1();
						callback(err, false);
					} else {
						let lines = out.stdout.split('\n');
						for(let i = 1; i <= lines.length - 1; i++) {
							if(lines[i].indexOf('X509v3 Subject Alternative Name') >= 1) {
								let start = lines[i + 1].split(':')[0].trim();
								cmd.push('-strparse ' + start);
								runOpenSSLCommand(cmd.join(' '), function(err, out) {
									if(err) {
										//console.log(err);
										cleanupCallback1();
										callback(err, false);
									} else {
										//console.log(out.stdout);
										let lines = out.stdout.split('\n');
										for(let j = 1; j <= lines.length - 1; j++) {
											if(lines[j].indexOf('cont [ 0 ]') >= 1) {
												if(lines[j + 1].indexOf('OBJECT') >= 1) {
													if(lines[j + 3].indexOf('UTF8STRING') >= 1) {
														let oid = lines[j + 1].split(':')[3].replace('\r','');
														if(oid.split('.').length >= 4) {
															otherNameSANs.push(oid + ';UTF8:' + lines[j + 3].split(':')[3].replace('\r',''));
														} else {
															otherNameSANs.push(oids[oid] + ';UTF8:' + lines[j + 3].split(':')[3].replace('\r',''));
														}
														//console.log(otherNameSANs);
														//console.log(lines[j + 3].split(':')[3].replace('\r',''));
														j = j + 1;
													}
												}
											}
										}
									}
									callback(null, otherNameSANs);
								});
								break;
							}
						}
					}
				});
			});
		});
	}
	
	var getKeyUsage = function(ku, callback) {
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
		callback(false, keyusage);
	}
	
	var getExtendedKeyUsage = function(eku, callback) {
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
			'IPSec User': 'ipsecUser',
			'1.3.6.1.4.1.311.20.2.1': '1.3.6.1.4.1.311.20.2.1'
		}
		var extendedkeyusages = eku.content[0].split(', ');
		if(eku.critical) extendedkeyusage.critical = true;
		extendedkeyusage['usages'] = [];
		for(var i = 0; i <= extendedkeyusages.length - 1; i++) {
			extendedkeyusage['usages'].push(index[extendedkeyusages[i]]);
		}
		callback(null, extendedkeyusage);
	}
	
	var getBasicConstraints = function(bc, callback) {
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
		callback(null, basicConstraints);
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
	
	var getDistinguishedName = function(subjectobj) {
		var index = {
			'countryName': 'C',
			'stateOrProvinceName': 'ST',
			'localityName': 'L',
			'postalCode': 'postalCode',
			'streetAddress': 'street',
			'organizationName': 'O',
			'organizationalUnitName': 'OU',
			'commonName': 'CN',
			'emailAddress': 'emailAddress',
			'jurisdictionLocalityName': 'jurisdictionL',
			'jurisdictionStateOrProvinceName': 'jurisdictionST',
			'jurisdictionCountryName': 'jurisdictionC',
			'serialNumber': 'serialNumber',
			'businessCategory': 'businessCategory'
		}
		
		let dn = [];
		
		try {
			var keys = Object.keys(subjectobj);
			for(let i = 0; i <= keys.length - 1; i++) {
				if(typeof(subjectobj[keys[i]])=='string') {
					dn.push('/' + index[keys[i]] + '=' + subjectobj[keys[i]].split(' ').join('\\ '))
				} else {
					for(let j = 0; j <= subjectobj[keys[i]].length - 1; j++) {
						dn.push('/' + index[keys[i]] + '=' + subjectobj[keys[i]][j].split(' ').join('\\ '));
					}
				}
			}	
		} catch(e) {
			dn.push('/');
		}
		return dn.join('');
	}
	
	this.getDistinguishedName = function(subjectobj) {
		return getDistinguishedName(subjectobj);
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
			'emailAddress': 'emailAddress',
			'jurisdictionL': 'jurisdictionLocalityName',
			'jurisdictionST': 'jurisdictionStateOrProvinceName',
			'jurisdictionC': 'jurisdictionCountryName',
			'serialNumber': 'serialNumber',
			'businessCategory': 'businessCategory'
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
				var splitsubject = trimSubjectAttrs(untrimmedsubject);
				//if subject is blank return now
				if(splitsubject.length <= 1 && splitsubject[0]=='') {
					return null;
				}
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
		//console.log(subject);
		return subject;
	}
	
	var getx509v3Attributes = function(certificate, originalcert, callback) {
		var parsedextensions = {};
		var x509v3 = certificate.split('\n');
		//console.log(x509v3);
		for(var i = 0; i <= x509v3.length - 1; i++) {
			if(x509v3[i].indexOf('X509v3') >= 0 || x509v3[i].indexOf('CT Precertificate SCTs') >= 0 || x509v3[i].indexOf('Authority Information Access') >= 0 || x509v3[i].indexOf('TLS Feature') >= 0 ) {
				var ext = x509v3[i].split(':');
				var extname = ext[0].replace('X509v3','').trim();
				//console.log(ext);
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
		
		//console.log(parsedextensions);
		
		/*for(var key in parsedextensions) {
			if(key=='Subject Alternative Name') {
				let SANs = getSubjectAlternativeNames(parsedextensions[key], originalcert);
				if(SANs) {
					extensions['SANs'] = SANs;
				}
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
		}*/
		//return null if there are no x509v3 extensions
		parseExtensions(originalcert, parsedextensions, false, 0, function(err, extensions) {
			if (Object.keys(extensions).length <= 0) {
				callback(null, null);
			} else {
				callback(null, extensions);
			}
		});
	}
	
	var parseExtensions = function(originalcert, parsedextensions, extensions, index, callback) {
		if(!extensions) {
			var extensions = {}
		}
		let ext = Object.keys(parsedextensions);
		if(ext.length > index) {
			//console.log(ext[index]);
			if(ext[index]=='Subject Alternative Name') {
				getSubjectAlternativeNames(parsedextensions[ext[index]], originalcert, function(err, attrs) {
					extensions['SANs'] = attrs;
					parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
				});
			} else if(ext[index]=='Key Usage') {
				getKeyUsage(parsedextensions[ext[index]], function(err, attrs) {
					extensions['keyUsage'] = attrs;
					parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
				});
			} else if(ext[index]=='Extended Key Usage') {
				getExtendedKeyUsage(parsedextensions[ext[index]], function(err, attrs) {
					extensions['extendedKeyUsage'] = attrs;
					parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
				});
			} else if(ext[index]=='Basic Constraints') {
				getBasicConstraints(parsedextensions[ext[index]], function(err, attrs) {
					extensions['basicConstraints'] = attrs;
					parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
				});
			} else if(ext[index]=='TLS Feature') {
				getTLSFeature(parsedextensions[ext[index]], function(err, attrs) {
					extensions['tlsfeature'] = attrs;
					parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
				});
			} else if(ext[index]=='Authority Information Access') {
				getAIA(parsedextensions[ext[index]], function(err, attrs) {
					extensions['authorityInfoAccess'] = attrs;
					parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
				});
			} else if(ext[index]=='CRL Distribution Points') {
				getCDP(parsedextensions[ext[index]], function(err, attrs) {
					extensions['crlDistributionPoints'] = attrs;
					parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
				});
			} else {
				parseExtensions(originalcert, parsedextensions, extensions, index + 1, callback);
			}
		} else {
			//console.log(extensions);
			callback(null, extensions);
		}
	}
	
	var getCDP = function(cdp, callback) {
		//console.log(cdp);
		let cdpitems = [];
		for(let i = 0; i <= cdp.content.length - 1; i++) {
			if(cdp.content[i].indexOf('URI:') >= 0) {
				cdpitems.push(cdp.content[i].replace('URI:', ''));
			}
		}
		if(cdpitems.length > 0) {
			callback(false, cdpitems);
		} else {
			callback(false, false);
		}
	}
	
	var getAIA = function(aia, callback) {
		//console.log(aia.content);
		var ocspitems = [];
		var aiaitems = [];
		//var valid = ['OCSP', 'CA Issuers']
		for(let i = 0; i <= aia.content.length - 1; i++) {
			//if(aia.content[i].split('-')[0].trim().indexOf()) {
			let attritem = aia.content[i].split(' - ')
			//console.log(valid.indexOf(attritem[0].trim()));
			if(attritem[0].trim() == 'OCSP') {
				ocspitems.push(attritem[1].trim().replace('URI:', ''));
			} else if(attritem[0].trim() == 'CA Issuers') {
				aiaitems.push(attritem[1].trim().replace('URI:', ''));
			} else {
				
			}
		}
		let authorityInfoAccess = false;
		if(ocspitems.length > 0 || aiaitems.length > 0) {
			authorityInfoAccess = {}
			if(ocspitems.length > 0) {
				authorityInfoAccess.OCSP = ocspitems;
			}
			if(aiaitems.length > 0) {
				authorityInfoAccess.caIssuers = aiaitems;
			}
			callback(false, authorityInfoAccess);
		} else {
			callback(false, false);
		}
	}
	
	var getTLSFeature = function(feature, callback) {
		var tlsfeature = []
		var index = {
			'status_request': 'status_request',
		}
		var tlsfeatures = feature.content[0].split(', ');
		for(var i = 0; i <= tlsfeatures.length - 1; i++) {
			tlsfeature.push(index[tlsfeatures[i]]);
		}
		callback(null, tlsfeature);
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
			} else if(attr=='Issuer') {
				outattrs[attr] = data[1].trim(' ');
			} else if(attr=='Subject') {
				outattrs['Subject String'] = data[1].trim(' ');
			} else if(attr.indexOf('Public-Key') >= 0) {
				outattrs['Public-Key'] = data[1].trim(' ').split(' ')[0].substring(1);
			} else if(attr.indexOf('challengePassword') >= 0) {
				outattrs['challengePassword'] = data[1].replace('\r','');
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
		if(lastline.indexOf('Fingerprint') >= 0) {
			outattrs['Thumbprint'] = lastline.split('=')[1].replace('\r\n','').replace('\r','').trim(' ');
		}
		return outattrs;
	}
	
	this.verifyChain = function(cert, chain, callback) {
		var cmd = [];
		tmp.file(function _tempFileCreated(err, certpath, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(certpath, cert, function() {
				tmp.file(function _tempFileCreated(err, chainpath, fd, cleanupCallback2) {
					if (err) throw err;
					fs.writeFile(chainpath, chain, function() {
						cmd.push('verify -CAfile ' + chainpath + ' ' + certpath);
						runOpenSSLCommand(cmd.join(), function(err, out) {
							//console.log(out);
							if(err) {
								callback(out.stderr, false, cmd.join());
							} else {
								if(out.stdout.indexOf(': OK\\')) {
									callback(false, 'OK', out.command.replace(certpath, 'cert.crt').replace(chainpath, 'chain.pem'));
								} else {
									callback(out.stdout, out.stdout, out.command.replace(certpath, 'cert.crt').replace(chainpath, 'chain.pem'));
								}
							}
							cleanupCallback1();
							cleanupCallback2();
						});
					});
				});
			});
		});
	}
	
	this.convertDERPKCS7toPEM = function(p7b, callback) {
		convertDERPKCS7toPEM(p7b, callback);
	}
	
	var convertDERPKCS7toPEM = function(p7b, callback) {
		var cmd = [];
		tmp.file(function _tempFileCreated(err, p7bpath, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(p7bpath, p7b, function() {
				cmd.push('pkcs7 -print_certs -inform DER -in ' + p7bpath);
				runOpenSSLCommand(cmd.join(), function(err, out) {
					//console.log(out);
					if(err) {
						callback(err, out.stderr, out.command.replace(p7bpath, 'cert.p7b'));
					} else {
						const begin = '-----BEGIN CERTIFICATE-----';
						const end = '-----END CERTIFICATE-----';
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
						callback(false, certs, out.command.replace(p7bpath, 'cert.p7b'));
					}
				});
			});
		});
	}
	
	this.getCertChain = function(cert, chain, callback) {
		getCertChain(cert, chain, callback);
	}
	
	var getCertChain = function(cert, chain, callback) {
		//console.log(chain);
		getCertInfo(cert, function(err, certinfo, cmd) {
			if(err) {
				callback(err, false);
			} else {
				//certinfo.base64 = cert;
				//console.log(certinfo);
				if(certinfo.extensions && certinfo.extensions.authorityInfoAccess && certinfo.extensions.authorityInfoAccess.caIssuers) {
					//console.log(certinfo.extensions.authorityInfoAccess.caIssuers[0]);
					downloadIssuer(certinfo.extensions.authorityInfoAccess.caIssuers[0], function(err, dcert) {
						if(err) {
							callback(err, false);
						} else {
							//console.log(dcert);
							//console.log(typeof(chain));
							//callback(false, [dcert]);
							chain.push(dcert.trim());
							getCertChain(dcert, chain, callback);
						}
					});
				} else {
					if(chain.length >= 0) {
						callback(false, chain);
					} else {
						callback('failed to download chain', false);
					}
				}
			}
		});
	}
	
	var getCertInfo = function(cert, callback) {
		var cmd = [];
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				cmd.push('x509 -in ' + path + ' -text -noout -fingerprint -nameopt utf8');
				runOpenSSLCommand(cmd.join(), function(err, out) {
					//console.log(out);
					if(err) {
						callback(out.stderr, false, cmd.join());
					} else {
						getx509v3Attributes(out.stdout, cert, function(err, extensions) {
							cleanupCallback1();
							if(err) {
								callback(err, false, cmd.join())
							} else {
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
						});
					}
				});
			});
		});
	}
	
	var getCSRInfo = function(cert, callback) {
		var cmd = [];
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				cmd.push('req -in ' + path + ' -text -noout -nameopt utf8');
				runOpenSSLCommand(cmd.join(), function(err, out) {
					//console.log(out);
					if(err) {
						callback(out.stderr,false,cmd.join());
					} else {
						getx509v3Attributes(out.stdout, cert, function(err, extensions) {
							cleanupCallback1();
							if(err) {
								callback(err, false, cmd.join())
							} else {
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
						});
					}
				});
			});
		});
	}
	
	this.getCSRInfo = function(cert, callback) {
		getCSRInfo(cert, callback);
	}
	
	this.getOpenSSLCertInfo = function(cert, callback) {
		var cmd = [];
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				cmd.push('x509 -in ' + path + ' -text -noout -fingerprint -nameopt utf8');
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
				cmd.push('x509 -in ' + path + ' -text -noout -nameopt utf8');
				runOpenSSLCommand(cmd.join(), function(err, out) {
					if(err) {
						callback(true,out.stderr,cmd.join());
					} else {
						getx509v3Attributes(out.stdout, cert, function(err, extensions) {
							var subject = getSubject(out.stdout);
							var csroptions = {
								extensions: extensions,
								subject: subject
							}
							//callback(false,out.stdout,cmd.join());
							callback(false,csroptions,'openssl ' + cmd.join().replace(path, 'cert.crt'));
						});
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	this.getCertHash = function(cert, hash, callback) {
		let hashtypes = ['sha256', 'sha1', 'md5']
		//console.log(hashtypes.indexOf(hash.toLowerCase()));
		if(hashtypes.indexOf(hash.toLowerCase()) >= 0) {
			tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
				if (err) throw err;
				fs.writeFile(path, cert, function() {
					var cmd = ['x509 -noout -fingerprint -' + hash.toLowerCase() + ' -inform pem -in ' + path + ' -nameopt utf8'];
					runOpenSSLCommand(cmd.join(' '), function(err, out) {
						if(err) {
							callback(true, false, out.command.replace(path, 'cert.pem'));
						} else {
							callback(false, out.stdout.split('=')[1], out.command.replace(path, 'cert.pem'));
						}
						cleanupCallback1();
					});
				});
			});
		} else {
			callback('invalid hash type', false, null);
		}
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
				//console.log(cmd.join(' '))
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

	var convertRSADERtoPEM = function(pubkey, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, pubkey, function() {
				var cmd = ['rsa -pubin -pubout -inform DER -outform PEM -in ' + path];
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					//console.log(out);
					if(err) {
						callback(true, false, out.command.replace(path, 'pubkey.pem'));
					} else {
						callback(false, out.stdout, out.command.replace(path, 'pubkey.pem'));
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	this.convertRSADERtoPEM = function(pubkey, callback) {
		convertRSADERtoPEM(pubkey, callback);
	}

	var convertECCDERtoPEM = function(pubkey, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, pubkey, function() {
				var cmd = ['ec -pubin -pubout -inform DER -outform PEM -in ' + path];
				runOpenSSLCommand(cmd.join(' '), function(err, out) {
					//console.log(out);
					if(err) {
						callback(true, false, out.command.replace(path, 'pubkey.pem'));
					} else {
						callback(false, out.stdout, out.command.replace(path, 'pubkey.pem'));
					}
					cleanupCallback1();
				});
			});
		});
	}
	
	this.convertECCDERtoPEM = function(pubkey, callback) {
		convertECCDERtoPEM(pubkey, callback);
	}

	var convertPrivPEMtoDER = function(params, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) {
				cleanupCallback1();
				callback(err, false, false);
			} else {
				fs.writeFile(path, params.key, function() {
					if(err) {
						cleanupCallback1();
						callback(err, false, false);
					} else {
						tmp.file(function _tempFileCreated(err, derpath, fd, cleanupCallback2) {
							if(err) {
								cleanupCallback1();
								cleanupCallback2();
								callback(err, false, false);
							} else {
								writePassword(params.password, function(err, passresp) {
									if(err) {
										callback(err, false);
									} else {
										let passcmd;
										if(params.password) {
											passcmd = '-passin file:' + passresp.path;
										} else {
											passcmd = '-passin pass:_PLAIN_';
										}
										var cmd = [params.type + ' -inform PEM ' + passcmd + ' -outform DER -in ' + path + ' -out ' + derpath];
										runOpenSSLCommand(cmd.join(' '), function(err, out) {
											//console.log(out);
											if(params.password) {
												passresp.cleanupCallback();
											}
											if(err) {
												cleanupCallback1();
												cleanupCallback2();
												callback(err, false, out.command.replace(path, 'key.pem').replace(derpath, 'key.der'));
											} else {
												fs.readFile(derpath, function(err, data) {
													cleanupCallback1();
													cleanupCallback2();
													if(err) {
														callback(err, false, out.command.replace(path, 'key.pem').replace(derpath, 'key.der'));
													} else {
														callback(false, data, out.command.replace(path, 'key.pem').replace(derpath, 'key.der'));
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
			}
		});
	}
	
	this.convertPrivPEMtoDER = function(pubkey, callback) {
		convertPrivPEMtoDER(pubkey, callback);
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
		downloadIssuer(uri, callback);
	}
	
	var downloadIssuer = function(uri, callback) {
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
							if(err) {
								//callback(err, false);
								convertDERPKCS7toPEM(Buffer.concat(data), function(err, cert, cmd) {
									if(err) {
										callback(err, false);
									} else {
										callback(false, cert[0]);
									}
								});
							} else {
								callback(false, cert);
							}
						});
					}
				});

			}).on("error", (err) => {
				callback(err, false);
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
							if(err) {
								convertDERPKCS7toPEM(Buffer.concat(data), function(err, cert, cmd) {
									if(err) {
										callback(err, false);
									} else {
										callback(false, cert[0]);
									}
								});
							} else {
								callback(false, cert);
							}
						});
					}
				});

			}).on("error", (err) => {
				callback(err, false);
			});
		}
	}
	
	this.getIssuerURI = function(cert, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback1) {
			if (err) throw err;
			fs.writeFile(path, cert, function() {
				var cmd = ['x509 -noout -in ' + path + ' -text -nameopt utf8'];
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
				var cmd = ['x509 -noout -in ' + path + ' -ocsp_uri -nameopt utf8'];
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
				writePassword(password, function(err, passresp1) {
					if(err) {
						callback(err, false);
					} else {
						writePassword(password, function(err, passresp2) {
							if(err) {
								callback(err, false);
							} else {
								if(password) {
									cmd.push('-passin file:' + passresp1.path + ' -passout file:' + passresp2.path);// + ' -passout pass:' + encryption.password + ' -' + encryption.cipher);
								} else {
									cmd.push('-nocrypt');
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
									if(password) {
										passresp1.cleanupCallback();
										passresp2.cleanupCallback();
									}
									cleanupCallback1();
								});
							}
						});
					}
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
			'ipsecUser',
			'1.3.6.1.4.1.311.20.2.1'
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
			'jurisdictionCountryName',
			'jurisdictionStateOrProvinceName',
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

		if(options.hasOwnProperty('module')) {
			if(options.module) {
				req.push('openssl_conf = openssl_def');
				req.push('[openssl_def]');
				req.push('engines = engine_section');
				req.push('[engine_section]');
				req.push('pkcs11 = pkcs11_section');
				req.push('[pkcs11_section]');
				req.push('engine_id = pkcs11');
				req.push('#dynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so');
				req.push('MODULE_PATH = ' + options.module);
				req.push('init = 0');
			}
		}
		
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
			//req.push('email_in_dn = no');
			req.push('[ signing_policy ]');
			req.push('countryName = optional');
			req.push('stateOrProvinceName = optional');
			req.push('localityName = optional');
			req.push('postalCode = optional');
			req.push('streetAddress = optional');
			req.push('organizationName = optional');
			req.push('organizationalUnitName = optional');
			req.push('commonName = optional');
			req.push('emailAddress = optional');
			req.push('jurisdictionCountryName = optional');
			req.push('jurisdictionStateOrProvinceName = optional');
			req.push('jurisdictionLocalityName = optional');
			req.push('businessCategory = optional');
			req.push('serialNumber = optional');
		}
		
		req.push('[ req ]');
		req.push('default_md = ' + options.hash);
		req.push('prompt = no');
		if(cert || options.extensions) {
			req.push('req_extensions = req_ext');
		}
		//if(options.subject) {
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
		//}
		if(options.extensions) {
			if(options.extensions.policies) {
				let policyconfig = generatePolicyConfig(options.extensions.policies);
				for(let i = 0; i <= policyconfig.length - 1; i++) {
					req.push(policyconfig[i]);
				}
			}
		}
		/*req.push('userNotice.1=@notice1');
		req.push('userNotice.2=@notice2');
		req.push('[notice1]');
		req.push('explicitText="I can write anything I want here"');
		req.push('organization="Organisation Name"');
		req.push('noticeNumbers=1,2,3,4');
		req.push('[notice2]');
		req.push('explicitText="I can write anything I want here"');
		req.push('organization="Organisation Name"');
		req.push('noticeNumbers=1,2,3,4');*/
		
		req.push('[ req_ext ]');
		/*if(options.mustStaple) {
			if(options.mustStaple==true) {
				req.push('1.3.6.1.5.5.7.1.24 = DER:30:03:02:01:05');
			}
		}*/
		if(cert) {
			//req.push('certificatePolicies = ia5org,2.5.29.32.0');
			req.push('subjectKeyIdentifier = hash');
			req.push('authorityKeyIdentifier = keyid:always,issuer');
		}
		if(options.extensions) {
			//req.push('[ req_ext ]');
			var endconfig = [];
			for(var ext in options.extensions) {
				if(ext == 'SANs') {
					if(options.extensions[ext]) {
						if(Object.keys(options.extensions[ext]).length >= 1) {
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
						}
					}
				} else if (ext == 'customOIDs') {
					if(options.extensions[ext]) {
						for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
							req.push(options.extensions[ext][i].OID + '=' + options.extensions[ext][i].value);
						}
					}
				} else if (ext == 'extendedKeyUsage') {
					if(options.extensions[ext]) {
						if(Object.keys(options.extensions[ext]).length >= 1) {
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
						}
					}
				} else if (ext == 'keyUsage') {
					if(options.extensions[ext]) {
						if(Object.keys(options.extensions[ext]).length >= 1) {
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
						}
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
					if(options.extensions[ext]) {
						if(Object.keys(options.extensions[ext]).length >= 1) {
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
						}
					}
				} else if (ext == 'authorityInfoAccess') {
					let aiaconfig = [];
					if(options.extensions[ext]['OCSP']) {
						for(var i = 0; i <= options.extensions[ext]['OCSP'].length - 1; i++) {
							aiaconfig.push('OCSP;URI.' + i + ' = ' + options.extensions[ext]['OCSP'][i]);
						}
					}
					if(options.extensions[ext]['caIssuers']) {
						for(var i = 0; i <= options.extensions[ext]['caIssuers'].length - 1; i++) {
							aiaconfig.push('caIssuers;URI.' + i + ' = ' + options.extensions[ext]['caIssuers'][i]);
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
				} else if (ext == 'policies') {
					if(options.extensions[ext].length > 0) {
						let policyIndexes = []
						//req.push('crlDistributionPoints = @crl_info');
						//endconfig.push('[ crl_info ]');
						for(var i = 0; i <= options.extensions[ext].length - 1; i++) {
							//endconfig.push('URI.' + i + ' = ' + options.extensions[ext][i]);
							if(options.extensions[ext][i]['policyIdentifier']) {
								policyIndexes.push('@polsect' + i);
							}
						}
						if(policyIndexes.length >= 1) {
							req.push('certificatePolicies = ia5org,' + policyIndexes.join(','));
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
	
	var generatePolicyConfig = function(policies) {
		let policyconfig = [];
		for(let i = 0; i <= policies.length - 1; i++) {
			policyconfig.push('[ polsect' + i + ' ]');
			policyconfig.push('policyIdentifier = ' + policies[i].policyIdentifier);
			if(policies[i].CPS) {
				if(typeof(policies[i].CPS)=='string') {
					policyconfig.push('CPS="' + policies[i].CPS +'"');
				} else {
					for(let j = 0; j <= policies[i].CPS.length - 1; j++) {
						policyconfig.push('CPS.' + j + '="' + policies[i].CPS[j] +'"');
					}
				}
			}
			if(policies[i].userNotice) {
				for(let j = 0; j <= policies[i].userNotice.length - 1; j++) {
					policyconfig.push('userNotice.' + j + '=@notice' + j);
				}
				for(let j = 0; j <= policies[i].userNotice.length - 1; j++) {
					policyconfig.push('[ notice' + j + ' ]');
					if(policies[i].userNotice[j].explicitText) {
						policyconfig.push('explicitText="' + policies[i].userNotice[j].explicitText + '"');
					}
					if(policies[i].userNotice[j].organization) {
						policyconfig.push('organization="' + policies[i].userNotice[j].organization + '"');
					}
					if(policies[i].userNotice[j].noticeNumbers) {
						policyconfig.push('noticeNumbers=' + policies[i].userNotice[j].noticeNumbers.join(','));
					}
				}
			}
		}
		/*policyconfig.push('[ polsect0 ]');
		policyconfig.push('policyIdentifier = 2.16.840.1.114412.2.1');
		policyconfig.push('CPS.1="https://certificatetools.com"');
		policyconfig.push('[ polsect1 ]');
		policyconfig.push('policyIdentifier = 2.23.140.1.2.1');*/
		
		//console.log(policyconfig);
		return policyconfig;
	}
	
	this.createPKCS7 = function(certs, outform, callback) {
		//console.log(typeof(certs));
		if(!outform) {
			outform = 'PEM';
		}
		tmp.file(function _tempFileCreated(err, p7bpath, fd, cleanupCallback1) {
			if (err) throw err;
			var cmd = ['crl2pkcs7 -nocrl -out ' + p7bpath + ' -outform ' + outform]
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
					fs.readFile(p7bpath, function(err, p7b) {
						cleanupCallback1();
						let p7bout;
						if(outform.toUpperCase()=='PEM') {
							p7bout = p7b.toString();
						} else {
							p7bout = p7b;
						}
						callback(false, p7bout, {
							command: [out.command]
						});
					});
				}
			});
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

	this.listPKCS11Slots = function(params, callback) {
		let slots = []
		let cmd = ['--list-slots'];
		if(params) {
			if(params.modulePath) {
				cmd.push('--module ' + params.modulePath);
			}
		}
		runPKCS11ToolCommand(cmd.join(' '), function(err, out) {
			if(err) {
				if(out.stderr.indexOf('No slots') == 0) {
					callback(false, [], out);
				} else {
					callback(err, false, out);
				}
			} else {
				let slot = {};
				let slotsexist = false;
				let lines = out.stdout.split('\n');
				for(let i = 1; i <= lines.length - 2; i++) {
					if(lines[i].indexOf('Slot') == 0) {
						if(slotsexist) {
							slots.push(slot);
							slot = {}
						}
						slotsexist = true;
						slot.id = lines[i].split(' (0x')[0].substring(5);
						//slot.id = parseInt(lines[i].split('): ')[0].substring(8), 16);
						slot.hexid = lines[i].split('): ')[0].substring(8);
						slot.name = lines[i].split('): ')[1]
						//console.log(slot);
					} else {
						let kvp = lines[i].split(':');
						if(kvp[0].trim()=='token flags') {
							slot[kvp.shift().trim()] = kvp.join(':').trim().split(', ');
						} else {
							slot[kvp.shift().trim()] = kvp.join(':').trim();
						}
						//console.log(kvp);
					}
				}
				if(slotsexist) {
					slots.push(slot);
				}
				callback(false, slots, out);
			}
		});
	}

	this.listPKCS11Objects = function(params, callback) {
		let objects = []
		let cmd = ['--list-objects'];
		if(params) {
			if(params.modulePath) {
				cmd.push('--module ' + params.modulePath);
			}
			if(params.slotid) {
				cmd.push('--slot ' + params.slotid);
			}
		}
		runPKCS11ToolCommand(cmd.join(' '), function(err, out) {
			if(err) {
				callback(err, false);
			} else {
				let object = {};
				let objectexist = false;
				let interesting = false;
				let interestingobjects = ['CERTIFICATE OBJECT', 'PUBLIC KEY OBJECT']
				let lines = out.stdout.split('\n');
				//console.log(lines);
				for(let i = 0; i <= lines.length - 2; i++) {
					//console.log(lines[i]);
					if(lines[i][0]==' ') {
						//console.log('property');
						if(interesting) {
							//console.log('pay attention');
							let examineproperty = lines[i].split(':');
							let key = examineproperty.shift().trim();
							if(key.toUpperCase()=='SUBJECT') {
								object[key] = examineproperty.join(':').replace('DN:' ,'').trim();
							} else if(key.toUpperCase()=='USAGE') {
								object[key] = examineproperty.join(':').trim().split(', ');
							} else {
								object[key] = examineproperty.join('').trim();
							}
						} else {
							//console.log('ignore');
						}
					} else {
						if(objectexist===true) {
							objects.push(object);
							object = {};
						}
						let examineobject = lines[i].split('; ');
						if(interestingobjects.includes(examineobject[0].toUpperCase())) {
							objectexist = true;
							interesting = true;
							//console.log(examineobject);
							object.type = examineobject[0]
							object.detail = examineobject[1].replace('type = ', '');
						} else {
							interesting = false;
						}
					}
				}
				if(objectexist) {
					objects.push(object);
				}
				callback(false, objects, out);
			}
		});
	}

	this.readPKCS11Object = function(params, callback) {
		tmp.file(function _tempFileCreated(err, derpath, fd, cleanupCallback) {
			if (err) {
				callback(err, false, false);
			} else {
				let cmd = ['--read-object --type ' + params.type + ' --id=' + params.objectid + ' --slot=' + params.slotid + ' --output-file ' + derpath];
				if(params) {
					if(params.modulePath) {
						cmd.push('--module ' + params.modulePath);
					}
				}
				runPKCS11ToolCommand(cmd.join(' '), function(err, out) {
					if(err) {
						callback(err, false, out);
					} else {
						fs.readFile(derpath, function(err, der) {
							cleanupCallback();
							if(err) {
								callback(err, false, out);
							} else {
								if(params.type=='cert') {
									convertDERtoPEM(der, function(err, pem) {
										if(err) {
											callback(err, false, out);
										} else {
											callback(false, pem, out);
										}
									});
								} else if(params.type=='pubkey'){
									convertRSADERtoPEM(der, function(err, pem) {
										//console.log(cmd.join(' '));
										if(err) {
											convertECCDERtoPEM(der, function(err, pem) {
												//console.log(cmd.join(' '));
												if(err) {
													callback(err, false, out);
												} else {
													callback(false, pem, out);
												}
											});
										} else {
											callback(false, pem, out);
										}
									});
								} else {
									callback('unrecogized type', false, false)
								}
							}
						});
					}
				});
			}
		});
	}

	this.CASignCSRv2 = function(params, callback) {
		//console.log(params.csr);
		params.options.days = typeof params.options.days !== 'undefined' ? params.options.days : 365;
		if(params.persistcapath) {
			generateConfig(params.options, true, params.persistcapath, function(err, req) {
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
								careq.push('base_dir = "' + params.persistcapath + '"');
							} else {
								careq.push(req[i]);
							}
						}
						//console.log(careq);
						fs.writeFile(config, careq.join('\r\n'), function() {
							var password = false;
							tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback2) {
								if (err) throw err;
								fs.writeFile(csrpath, params.csr, function() {
									var cmd = ['ca -config ' + config + ' -create_serial -in ' + csrpath + ' -policy signing_policy -batch -notext -utf8'];
									if(params.options.hasOwnProperty('subject')) {
										if(params.options.subject===false || params.options.subject===null) {
											cmd.push('-subj /')
										} else {
											cmd.push('-subj ' + getDistinguishedName(params.options.subject));
										}
									}
									if(params.options.startdate) {
										cmd.push('-startdate ' + moment(params.options.startdate).format('YYYYMMDDHHmmss') + 'Z -enddate ' + moment(params.options.enddate).format('YYYYMMDDHHmmss') + 'Z');
									} else {
										cmd.push('-days ' + params.options.days);
									}
									if(params.password) {
										password = params.password;
										cmd.push('-passin stdin');
									}
									if(params.hasOwnProperty('pkcs11')) {
										if(params.pkcs11===false || params.pkcs11===null) {
											//cmd.push('-subj /')
										} else {
											password = params.pkcs11.pin;
											cmd.push('-engine pkcs11 -keyform engine -keyfile pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.slotid + ' -passin stdin' );
										}
									}
									runOpenSSLCommandv2({ cmd: cmd.join(' '), stdin: password}, function(err, out) {
										if(err) {
											callback(err, out.stdout, {
												command: [out.command.replace(config, 'config.txt').replace(csrpath, 'cert.csr')],
												files: {
													config: req.join('\r\n')
												}
											});
										} else {
											fs.readFile(params.persistcapath + '/serial.txt', function(err, serial) {
												callback(false, out.stdout, {
													command: [out.command.replace(config, 'config.txt').replace(csrpath, 'cert.csr')],
													serial: serial.toString().replace('\r\n', '').replace('\n', ''),
													files: {
														config: req.join('\r\n')
													}
												});
											});
										}
										if(params.password) {
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
			generateConfig(params.options, true, false, function(err, req) {
				if(err) {
					callback(err,{
						command: null,
						data: null
					});
					return false;
				} else {
					tmp.file(function _tempFileCreated(err, capath, fd, cleanupCallback1) {
						if (err) throw err;
						fs.writeFile(capath, params.ca, function() {
							tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback2) {
								if (err) throw err;
								fs.writeFile(csrpath, params.csr, function() {
									tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback3) {
										if (err) throw err;
										fs.writeFile(keypath, params.key, function() {
											tmp.file(function _tempFileCreated(err, csrconfig, fd, cleanupCallback4) {
												if (err) throw err;
												fs.writeFile(csrconfig, req.join('\r\n'), function() {
													tmp.tmpName(function _tempNameGenerated(err, serialpath) {
														if (err) throw err;
														//fs.writeFile(serialpath, req.join('\r\n'), function() {
															var cmd = ['x509 -req -in ' + csrpath + ' -days ' + params.options.days + ' -CA ' + capath + ' -extfile ' + csrconfig + ' -extensions req_ext -CAserial ' + serialpath + ' -CAcreateserial -nameopt utf8'];
															//var cmd = ['x509 -req -in ' + csrpath + ' -days ' + params.options.days + ' -CA ' + capath + ' -CAkey ' + keypath + ' -extfile ' + csrconfig + ' -extensions req_ext'];
															if(params.options.hash) {
																cmd.push('-' + params.options.hash);
															}
															if(params.password) {
																var passfile = tmp.fileSync();
																fs.writeFileSync(passfile.name, params.password);
																cmd.push('-passin file:' + passfile.name);
															}
															if(params.hasOwnProperty('pkcs11')) {
																if(params.pkcs11===false || params.pkcs11===null) {
																	cmd.push('-CAkey ' + keypath);
																} else {
																	cmd.push('-engine pkcs11 -CAkeyform engine -CAkey pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.slotid + ';type=private -passin pass:' + params.pkcs11.pin );
																}
															} else {
																cmd.push('-CAkey ' + keypath);
															}
													
													//console.log(cmd);
													
													runOpenSSLCommandv2({ cmd: cmd.join(' ') }, function(err, out) {
																if(err) {
																	callback(err, out.stdout, {
																		command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'cert.csr').replace(capath, 'ca.crt').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
																		files: {
																			config: req.join('\r\n')
																		}
																	});
																} else {
																	fs.readFile(serialpath, function(err, serial) {
																		
																		fs.unlink(serialpath, function(err) {
																			//delete temp serial file
																		});
																		
																		callback(false, out.stdout, {
																			command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'cert.csr').replace(capath, 'ca.crt').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
																			serial: serial.toString().replace('\r\n', '').replace('\n', ''),
																			files: {
																				config: req.join('\r\n')
																			}
																		});
																	});
																}
																if(params.password) {
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
									var cmd = ['ca -config ' + config + ' -create_serial -in ' + csrpath + ' -policy signing_policy -batch -notext -utf8'];
									if(options.hasOwnProperty('subject')) {
										if(options.subject===false || options.subject===null) {
											cmd.push('-subj /')
										} else {
											cmd.push('-subj ' + getDistinguishedName(options.subject));
										}
									}
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
															var cmd = ['x509 -req -in ' + csrpath + ' -days ' + options.days + ' -CA ' + capath + ' -CAkey ' + keypath + ' -extfile ' + csrconfig + ' -extensions req_ext -CAserial ' + serialpath + ' -CAcreateserial -nameopt utf8'];
															//var cmd = ['x509 -req -in ' + csrpath + ' -days ' + options.days + ' -CA ' + capath + ' -CAkey ' + keypath + ' -extfile ' + csrconfig + ' -extensions req_ext'];
															if(options.hash) {
																cmd.push('-' + options.hash);
															}
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
																		
																		fs.unlink(serialpath, function(err) {
																			//delete temp serial file
																		});
																		
																		callback(false, out.stdout, {
																			command: [out.command.replace(keypath, 'priv.key').replace(csrpath, 'cert.csr').replace(capath, 'ca.crt').replace(csrconfig, 'certconfig.txt') + ' -out cert.crt'],
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
										var cmd = ['req -x509 -nodes -in ' + csrpath + ' -days ' + options.days + ' -key ' + keypath + ' -config ' + csrconfig + ' -extensions req_ext -nameopt utf8 -utf8'];
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

	this.selfSignCSRv2 = function(params, callback) {
		//console.log(csr);
		params.options.days = typeof params.options.days !== 'undefined' ? params.options.days : 365;
		generateConfig(params.options, true, false, function(err, req) {
			if(err) {
				callback(err,{
					command: null,
					data: null
				});
				return false;
			} else {
				tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback1) {
					if (err) throw err;
					fs.writeFile(csrpath, params.csr, function() {
						tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback2) {
							if (err) throw err;
							fs.writeFile(keypath, params.key, function() {
								tmp.file(function _tempFileCreated(err, csrconfig, fd, cleanupCallback3) {
									if (err) throw err;
									fs.writeFile(csrconfig, req.join('\r\n'), function() {
										var cmd = ['req -x509 -nodes -days ' + params.options.days + ' -config ' + csrconfig + ' -extensions req_ext -nameopt utf8 -utf8'];
										if(params.hasOwnProperty('pkcs11')) {
											if(params.pkcs11===false || params.pkcs11===null) {
												cmd.push('-key ' + keypath);
											} else {
												cmd.push('-engine pkcs11 -keyform engine -key pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.slotid + ' -passin pass:' + params.pkcs11.pin );
											}
										} else {
											cmd.push('-key ' + keypath);
										}
										if(params.password) {
											var passfile = tmp.fileSync();
											fs.writeFileSync(passfile.name, params.password);
											cmd.push('-passin file:' + passfile.name);
										}
										if(params.csr) {
											cmd.push('-in ' + csrpath);
										} else {
											cmd.push('-new');
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
											if(params.password) {
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
								var cmd = ['req -new -nodes -key ' + keypath + ' -config ' + csrpath + ' -nameopt utf8 -utf8'];
								//allows openssl to have a blank subject
								if(!options.subject) {
									cmd.push('-subj /')
								}
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

	this.generateCSRv2 = function(params, callback) {
		var password = 'fakepassword';
		generateConfig(params.options, false, false, function(err, req) {
			if(err) {
				callback(err,{
					command: null,
					data: null
				});
				return false;
			} else {
				tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback1) {
					if (err) throw err;
					fs.writeFile(keypath, params.key, function() {
						tmp.file(function _tempFileCreated(err, csrpath, fd, cleanupCallback2) {
							if (err) throw err;
							fs.writeFile(csrpath, req.join('\r\n'), function() {
								var cmd = ['req -new -nodes -config ' + csrpath + ' -nameopt utf8 -utf8 -passin stdin'];
								if(params.hasOwnProperty('pkcs11')) {
									if(params.pkcs11===false || params.pkcs11===null) {
										cmd.push('-key ' + keypath);
									} else {
										password = params.pkcs11.pin;
										cmd.push('-engine pkcs11 -keyform engine -key pkcs11:serial=' + params.pkcs11.serial + ';id=%' + params.pkcs11.slotid);
									}
								} else {
									cmd.push('-key ' + keypath);
								}
								//allows openssl to have a blank subject
								if(!params.options.subject) {
									cmd.push('-subj /')
								}
								if(params.password) {
									password = params.password
								}
						
						//console.log(cmd);
						
								runOpenSSLCommandv2({ cmd: cmd.join(' '), stdin: password }, function(err, out) {
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
	
	var writePassword = function(password, callback) {
		if(password) {
			tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
				if(err) {
					callback(err, false);
				} else {
					fs.writeFile(path, password, function(err) {
						if(err) {
							callback(err, false);
						} else {
							callback(err, {path: path, password: password, cleanupCallback: cleanupCallback});
						}
					});
				}
			});
		} else {
			callback(false, {path: false, password: false, cleanupCallback: false});
		}
	}
	
	this.encryptECCPrivateKey = function(key, cipher, password, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(path, key, function(err) {
				if(err) {
					callback(err, false);
				} else {
					writePassword(password, function(err, passresp) {
						if(err) {
							callback(err, false);
						} else {
							let cmd = ['ec -' + cipher + ' -in ' + path + ' -passin pass:FAKE -passout file:' + passresp.path];
							runOpenSSLCommand(cmd.join(' '), function(err, out1) {
								cleanupCallback()
								passresp.cleanupCallback()
								if(err) {
									callback(err, false, null);
								} else {
									convertToPKCS8Encrypt(out1.stdout, password, function(err, out2) {
										//console.log(out2);
										if(err) {
											callback(err, false);
										} else {
											callback(false, out2.data, [out1.command + ' -out priv.key']);
										}
									});
								}
							});
						}
					});
				}
			});
		});
	}
	
	this.checkRSAMatch = function(key, keypass, cert, callback) {
		tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback1) {
			if(err) {
				callback(err, false);
			} else {
				fs.writeFile(keypath, key, function(err) {
					if(err) {
						callback(err, false);
					} else {
						tmp.file(function _tempFileCreated(err, certpath, fd, cleanupCallback2) {
							if(err) {
								callback(err, false);
							} else {
								fs.writeFile(certpath, cert, function(err) {
									if(err) {
										callback(err, false);
									} else {
										writePassword(keypass, function(err, passresp) {
											if(err) {
												callback(err, false);
											} else {
												let passcmd;
												if(keypass) {
													passcmd = '-passin file:' + passresp.path;
												} else {
													passcmd = '-passin pass:_PLAIN_';
												}
												let cmd = ['rsa ' + passcmd + ' -in ' + keypath + ' -pubout'];
												//console.log(cmd.join(' '));
												runOpenSSLCommand(cmd.join(' '), function(err, out1) {
													if(keypass) {
														passresp.cleanupCallback()
													}
													cleanupCallback1()
													if(err) {
														callback(err, false);
													} else {
														let cmd = ['x509 -in ' + certpath + ' -noout -pubkey'];
														runOpenSSLCommand(cmd.join(' '), function(err, out2) {
															cleanupCallback2()
															if(err) {
																callback(err, false);
															} else {
																let key = crypto.createHash('sha256').update(out1.stdout).digest('hex');
																let cert = crypto.createHash('sha256').update(out2.stdout).digest('hex');
																//console.log(out1.stdout);
																//console.log(out2.stdout);
																if(key===cert) {
																	callback(false, true);
																} else {
																	callback(false, false);
																}
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
					}
				});
			}
		});
	}
	
	this.checkECCMatch = function(key, keypass, cert, callback) {
		tmp.file(function _tempFileCreated(err, keypath, fd, cleanupCallback1) {
			if(err) {
				callback(err, false);
			} else {
				fs.writeFile(keypath, key, function(err) {
					if(err) {
						callback(err, false);
					} else {
						tmp.file(function _tempFileCreated(err, certpath, fd, cleanupCallback2) {
							if(err) {
								callback(err, false);
							} else {
								fs.writeFile(certpath, cert, function(err) {
									if(err) {
										callback(err, false);
									} else {
										writePassword(keypass, function(err, passresp) {
											if(err) {
												callback(err, false);
											} else {
												let passcmd;
												if(keypass) {
													passcmd = '-passin file:' + passresp.path;
												} else {
													passcmd = '-passin pass:_PLAIN_';
												}
												let cmd = ['ec ' + passcmd + ' -in ' + keypath + ' -pubout'];
												//console.log(cmd.join(' '));
												runOpenSSLCommand(cmd.join(' '), function(err, out1) {
													if(keypass) {
														passresp.cleanupCallback()
													}
													cleanupCallback1()
													if(err) {
														callback(err, false);
													} else {
														let cmd = ['x509 -in ' + certpath + ' -noout -pubkey'];
														runOpenSSLCommand(cmd.join(' '), function(err, out2) {
															cleanupCallback2()
															if(err) {
																callback(err, false);
															} else {
																let key = crypto.createHash('sha256').update(out1.stdout).digest('hex');
																let cert = crypto.createHash('sha256').update(out2.stdout).digest('hex');
																//console.log(out1.stdout);
																//console.log(out2.stdout);
																if(key===cert) {
																	callback(false, true);
																} else {
																	callback(false, false);
																}
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
					}
				});
			}
		});
	}
	
	this.encryptRSAPrivateKey = function(key, cipher, password, callback) {
		tmp.file(function _tempFileCreated(err, path, fd, cleanupCallback) {
			if (err) throw err;
			fs.writeFile(path, key, function(err) {
				if(err) {
					callback(err, false);
				} else {
					writePassword(password, function(err, passresp) {
						if(err) {
							callback(err, false);
						} else {
							let cmd = ['rsa -' + cipher + ' -in ' + path + ' -passin pass:FAKE -passout file:' + passresp.path];
							runOpenSSLCommand(cmd.join(' '), function(err, out1) {
								cleanupCallback()
								passresp.cleanupCallback()
								if(err) {
									callback(err, false, null);
								} else {
									convertToPKCS8Encrypt(out1.stdout, password, function(err, out2) {
										//console.log(out2);
										if(err) {
											callback(err, false);
										} else {
											callback(false, out2.data, [out1.command + ' -out priv.key']);
										}
									});
								}
							});
						}
					});
				}
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
