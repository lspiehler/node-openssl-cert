const node_openssl = require('../index.js');
const name_mappings = require('../name_mappings');

var openssl = new node_openssl({});

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
			'أقسام الشروحات',
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
				'google.com',
				'www.google.com'
			]
		}
	}
}

let keys = Object.keys(name_mappings);
csroptions.extensions.SANs.otherName = [];
csroptions.extensions.SANs.otherName.push('nsSGC;UTF8:example othername');
csroptions.extensions.SANs.otherName.push('msEFS;UTF8:example othername');
csroptions.extensions.SANs.otherName.push('nsSGC;UTF8:example othername');
csroptions.extensions.SANs.otherName.push('msCTLSign;UTF8:example othername');
csroptions.extensions.SANs.otherName.push('msCodeInd;UTF8:example othername');
csroptions.extensions.SANs.otherName.push('msCodeCom;UTF8:example othername');
csroptions.extensions.SANs.otherName.push('secureShellServer;UTF8:example othername');
//csroptions.extensions.SANs.otherName = [];
//for (let i = 0; i < keys.length; i++) {
for (let i = 0; i < keys.length; i++) {
    //csroptions.extensions.SANs.otherName.push(name_mappings[keys[i]] + ';UTF8:huge csr test');
}

console.log(csroptions.extensions.SANs.otherName);

//var path = 'C:/Users/Lyas/Desktop/nodetest/cadir';
openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
    openssl.generateCSR(csroptions, key, false, function(err, csr, cmd) {
        if(err) {
            console.log(err);
            //console.log(cmd);
        } else {
            //console.log(cmd);
            console.log(csr);
            openssl.getCSRInfo(csr, function(err, attrs, cmd) {
				if(err) {
					console.log(err);
				} else {
					console.log(attrs);
				}
			});
        }
    });
});