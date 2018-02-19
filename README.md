# node-openssl-cert
Node.JS OpenSSL wrapper for creating and converting private keys, generating CSRs, etc.
###Installation

```
npm install node-openssl-cert
```

### Usage
Load and instantiate node-openssl-cert
```
const node_openssl = require('node-openssl-cert');
const openssl = new node_openssl();
```

Generate an RSA privatekey with the default options and show the openssl command used to create it.
```
openssl.generateRSAPrivateKey({}, function(err, key, cmd) {
	console.log(cmd);
	console.log(key);
});
```
Will return like this:
```
[ 'openssl genpkey -outform PEM -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key' ]
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDjnDud8ysybn1Y
CJd6iYORtt9zya6w/vaeRRQzmSgkOcA2xqaN0PxwgYk+pUSLBgmgTVXaaSZtleX1
7safXdze1a4lCtoTOxWG5awOgfmZL9ZMqY4PumM4VsN6K1oIWxHthRudisOldYUx
Sn6iDWtZBem1pGAm/IiTRQbgrs/okw7HEO0j18ZqsTpWXyq/hRMDRYajgWemkeLD
FVMvWdroY9RDalXTy1qec+Ic8NBpE9I3FZlHdFd0hJB4V/OpoC+5OaCdQiIoPkeO
ZJMjs/2DYGr0Lh0UWBfgpxT2eDpXKFuQUDiFwAa2vuXkrqWMjcR7naU2QaaymvAm
hV3IWmQ7AgMBAAECggEANOvwmKsfkhxKnJtyzRUIOGsyzXNJYPIHWYlqRw0HXlTn
MlVCCJtc9rPHu38lzsVam6EfoybrvnMqAuK/3/ItFsrMMOSzC+GjAbiJJt5lsI6E
31JVK6cExua1kMRfrK2wH2/hmeHX17LZgzp08yz3lr1fN9K+YJI7FzLnhHpg8QxA
ENCfib29NS0poIGg0sX3VSI1RPhicQyBm2hgjllawIhnA8fkz+K76tDvbgU8uZWQ
z23MGmg2qbejzIDR8GckKBeTCVTOxktLDWHWxdGl94/K0Q4NYMVb/XSDR/CTKvmB
6Ll5abYrOF8sf/2mPsYlNirBb6EvniRk6lo70KK/4QKBgQD1ePMGbF5YqlySaJWC
gF2vRJgdDhyETzt3d6D/vivvIfsy0zDgUR8qqnzNH0wL1IZ7JYwFcqPmJJjRdiea
fzlY6LLs1snOuhIx1jw1Z8pfJALO39nuN/3h/Hpw3f+2PG9ozBjww26zjPqrmQnN
TeH/oFT7DTupzJY8N+bndd9nqQKBgQDtXyyUHwrVoLToNizSnBzFKr5Oe2SyQsIh
YC+dN0moAVuRVz6Fz2xRDodS1S2CGvK0j6mSnkaYufVDW3zh1KtfyCoMKYar4ZZ5
XcIVojwk9GL6t4tHtgknbfXcO+NHZXi5NJXc0sFVEbxZwmJyXKLDrOHsApufTLNO
LZme9r4LQwKBgCc6KdQH81fF+b8n2WSecNo2YvyZqbL3GnCv/FmCIXE4g/UOTMw8
Cnf+AK2i57soPkllqaehN1Hq3UTz1cZZuGdd4GH6vQs9LvUp4DtEl9F2ZsB6g1AP
QJIhj8uDnn6Xz9H2c7Hd+U3WJKTRcwCNBqWcEJiB99vdptB+unaYnpfpAoGAShZF
jKmvsQOq0zttfAK7vBJeOZKr2DOb8dzan6BM/gIGeXOYkR0vepElTYY54PzWOeMJ
EzkRYcPQuEhKzxWYs5l+/jLL1MPhOlo4JJZxXTtl1UkKUMSRUNwyO535jyQtrOir
ybOCIjIZ7o4MOhONvbMtBIO/3NWMtV7oLsRmho8CgYB5qx6eVB44rn9T4pzE1UEK
k/KrtzLRBjCJfqWhYfbTDOzItqQEjzmVmTZxLHl3TIR9xYgcqKTD91y+cwl3j35g
7fpidBDjqZmP2vUNav8l95yq94iC95e80QSBHgpMHkaRqSpj3P5NaOG8zGxwOZ1x
Ke97vdVom/vmhxgbok9skQ==
-----END PRIVATE KEY-----
```
Generate an RSA private key with custom options and show the openssl command used to create it.
```
var rsakeyoptions = {
	encryption: {
		password: 'test',
		cipher: 'des3'
	},
	rsa_keygen_bits: 2048,
	rsa_keygen_pubexp: 65537,
	format: 'PKCS8'
}

openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
	console.log(cmd);
	console.log(key);
});
```
Will return like this:
```
[ 'openssl genpkey -outform PEM -algorithm RSA -pass pass:test -des3 -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out rsa.key' ]
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIS10INHjYe7ECAggA
MBQGCCqGSIb3DQMHBAjL6y04rNxnowSCBMgs4NLlXMJsI2c/ZYNpKg3aLXCdyr3T
2kIZRURTzBziP4gBGRNwjJqb/4xbp2H1XXB9l8BMdlDFDaqi0xnPxJdu7lJAHi71
TJ7RCb7RxsuLVqjUbq6TYEPuAaS+KCHfEy/aCJx6oyGWkyJaoLl97lxIZ+TnVKxs
LWN4PwclYJbX0LbXNJblanHqBAw/5ggl95PlpxidLL8K9Gvm2SfFCMoGpBCT8vJl
YtUECFlV/gBW467nhcLdODNNk06D34AxUWvcP4ELAAx7aj7NMNx3xRjbWW5cHpfy
RMsaL+26vEhX2RKDgqsUZ6vhk0qLTxlpI+gaqyvTZsShtEU1CbESn0vSKb8tuJSq
Rw1kDxCXkNHG1tJimeMVGt27sUvhIP1HqEwPBTF1iGAaulruPGmlchGAMpIvW+4I
++Kmf2ezaFCASi9ggn9Xm2jupJOaxJQ1cTdPZzJx9zqUMC/cVrps7QSPLM+4mIzB
XCNl9JU6tAsKI49tWn9QSbvE8fiEPOnPLbGnQL21VNHFOCaVVPKL849QLS37rKXd
gf16eO80UD51CZU4ZibUhL+IgVONFZj4Pbh+GJh5Mr7E/pghvJUNKvnBnhLsRwYx
BEHN8mEQmju1kZLlT+N4dAOBOKH+Fu9TqTAaC8FM5+FDLFRlfBKF8prwvjvKGmYF
edy+co0fd6Q8VpWTHNAmQIV4MDqRLj7vncB8GyX5C8ety6MMLdKLG5ZgqVP28BHy
+QyMhpAUmBPWpblvZ/GdTynatuZe1Cra7SKqDdDOJEbPXeNuuo2bVYwFQszC+682
3lOI3ghQeB3ghRlCtRipkO04y3+L6ytX2tZsoBvV1EhpXWP6rrkD1PuZc4sWNpDy
cN88ga20Ee+WcNkNSPjseULnCEAy1H/waewhL040q3hbpDgla8bWbZHvs17yvlPx
JOKlhan2sXuahbi0vua6B6bJ0qJktpKNqIjuQRrqNISTsKdKiYAHgcz58r3tmXIP
wHB4KmfSW+2xMm5sYrrCmZ8+1TYBMx1egMBYhmV6X3jQGDZp3KpKPA5hb+J8kJfa
PyZXJW85h368XNU3G7CE6Vo7p8F7in3gEa78ZMNko5JNFrV2LWd/lyl8xEZKklF6
RcBFRCta/08eLcOmGJssbVsa4tuxIKFceyVG7axhy4VIYLbjLKERUrDsjcE303Fh
f+UVI/UH2k3CgfyXUOXdNP2EZyHFrH2E36nTb4nLzaB7tKoYeg+YKQFMQnNtTmck
7fuzXUiWuEmxkkw9D4WoFExc4BPXX40Oa2bzUzwWML3sBREY0UJK0+J02bumJ5wf
Nyr0NHUKw6ZZOI5V1nrLgjcWGD0jxpHcyDFR6nqlXo9VfjXdIGfSQ9HfzOVc/uJn
lciM8BvkDUO1sDzEt4njHsk9OdVZw2nbgZa6vZHK5aulNJ19CUdXtiwitNRkLbuB
HpnCrdkLKAFGJhx0PqsUPRIMDTDgn/cmBgYwIIOcFy+tYKh89XT14xEvSj2XH6qD
/GUVBs2sFzId5fbrRwkTUIS/oadQFTBJbWHXs2bKLRMg5PbblDvvTTFHuq10CiwT
alHa+0pTuWFxNCyACxt6ZzpB4n0K9tV5HUC1Fri+JNgkBslzZelHNDm6P7aldxtg
LSo=
-----END ENCRYPTED PRIVATE KEY-----
```
Generating a private key with custom options and using it to generate a CSR showing the commands for both and the openssl config for the CSR.
```
var rsakeyoptions = {
	encryption: {
		password: 'test',
		cipher: 'des3'
	},
	rsa_keygen_bits: 2048,
	rsa_keygen_pubexp: 65537,
	format: 'PKCS8'*/
}

var csroptions = {
	hash: 'sha512',
	subject: {
		countryName: 'US',
		stateOrProvinceName: 'Louisiana',
		localityName: 'Slidell',
		postalCode: '70458',
		streetAddress: '1001 Gause Blvd.',
		organizationName: 'SMH',
		organizationalUnitName: 'IT',
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
			//critical: false,
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

openssl.generateRSAPrivateKey(rsakeyoptions, function(err, key, cmd) {
	console.log(cmd);
	console.log(key);
	openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
		if(err) {
			console.log(err);
		} else {
			console.log(cmd.command);
			console.log(csr);
			console.log(cmd.files.config);
		}
			
	});
});
```