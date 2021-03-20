const node_openssl = require('../index.js');
const cryptoRandomString = require('crypto-random-string');

var options = {
	//binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
	binpath: 'openssl'
}

var openssl = new node_openssl(options);

var rsakeyoptions = {
	rsa_keygen_bits: 2048,
	format: 'PKCS8'
}

var randomizeCSR = function() {
    let randomstring = cryptoRandomString({length: 10, characters: 'abcdefghijklmnopqrstuvwxyz'});
    return csroptions = {
        hash: 'sha256',
        string_mask: 'nombstr',
        requestAttributes: {
            challengePassword: challenge,
            //unstructuredName: 'Optional Company Name'
        },
        subject: {
            countryName: 'US',
            stateOrProvinceName: 'Louisiana',
            localityName: 'Slidell',
            commonName: [
                randomstring + '.scep.test'
            ],
        },
        extensions: {
            SANs: {
                DNS: [
                    randomstring + '.scep.test'
                ]
            }
        }
    }
}

//let scepurl = 'http://pkiaas.io/scep/w7Gxq4zZH9'
//let scepurl = 'http://cyopki.com/scep/f5IK8ghmT0'
//var challenge = '0UZCT2UZSF6S1HFO';
//yubikey
//let scepurl = 'http://cyopki.com/scep/qHMRSEatVs'
//var challenge = '0RK6E40H1FM29MBD';
//double yubikey cyopki
var scepurl = 'http://cyopki.com/scep/UdZOhBULg3';
var challenge = '0W70LPBEIZXN911L';
//double yubikey pkiaas
//var scepurl = 'http://pkiaas.io/scep/lGEd3QUkut';
//var challenge = '0EDV4H214NOSVKHO';

//var count = 0;

/*for(let i = 0; i <= 75; i++) {
    openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
        if(err) {
            console.log('key');
            console.log(err);
        } else {
            //console.log(key);
            openssl.generateCSRv2({options: randomizeCSR(), key: key}, function(err, csr, cmd) {
                if(err) {
                    console.log('csr');
                    console.log(err);
                } else {
                    //count++;
                    console.log(csr);
                }
            });
        }
    })
}*/

//console.log(count);

function sendSCEPRequests(count) {
    for(let i = 0; i <= count; i++) {
        openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
            if(err) {
                console.log(err);
            } else {
                openssl.generateCSRv2({options: randomizeCSR(), key: key}, function(err, csr, cmd) {
                    if(err) {
                        console.log(err);
                        console.log(key);
                    } else {
                        //console.log(csr);
                        openssl.SCEPRequest({csr: csr, key: key, scepurl: scepurl}, function(err, out) {
                            if(err) {
                                console.log(err);
                                console.log(out);
                            } else {
                                openssl.createPKCS12(out, key, false, false, false, function(err, pfx, command) {
                                    if(err) {
                                        console.log(err);
                                    } else {
                                        console.log('success');
                                    }
                                });
                                //console.log(openssl.getDistinguishedName(attrs.subject));
                            }
                        });
                    }
                });
            }
        });
    }
}

sendSCEPRequests(2);

setTimeout(function() {sendSCEPRequests(2)}, 2000);