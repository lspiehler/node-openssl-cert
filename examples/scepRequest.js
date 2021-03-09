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
            challengePassword: '0UZCT2UZSF6S1HFO',
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
let scepurl = 'http://cyopki.com/scep/f5IK8ghmT0'

for(let i = 0; i <= 4; i++) {
    openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
        if(err) {
            console.log(err);
        } else {
            //console.log(key);
            openssl.generateCSR(randomizeCSR(), key, false, function(err, csr, cmd) {
                if(err) {
                    console.log(err);
                } else {
                    //console.log(csr);
                    openssl.SCEPRequest({csr: csr, key: key, scepurl: scepurl}, function(err, out) {
                        if(err) {
                            console.log(err);
                        } else {
                            console.log(out);
                            //console.log(openssl.getDistinguishedName(attrs.subject));
                        }
                    });
                }
            });
        }
    });
}