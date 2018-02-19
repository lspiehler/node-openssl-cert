# node-openssl-cert
Node.JS OpenSSL wrapper for creating and converting private keys, generating CSRs, etc.

### Requirements

Make sure the OpenSSL binary is installed and located in the system path

#### Windows

Download installer from https://slproweb.com/products/Win32OpenSSL.html (Light version is sufficient)

#### Debian/Ubuntu Linux
```
apt install openssl
```

#### RedHat/CentOS Linux
```
yum install openssl
```

### Installation

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
Will return like this:
```
[ 'openssl genpkey -outform PEM -algorithm RSA -pass pass:test -des3 -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -out rsa.key' ]
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIGygSM8eJHg8CAggA
MBQGCCqGSIb3DQMHBAjR9LqF/JED0ASCBMjbgofGddW4epbJN4xfHjkhTmr+S7dA
PPkZsMmj/7oXVox7pxpQ3w4zJJdg2PQdCf7aMjE5aE2N7bKHTw8CYuofQqmpiJOp
svtD33qxPwLJ3g3jqf0ptIVn+TpPbCWG04E0kwblwgkI+3jyIPit4D+GhQp05khs
Iy7DBK3KqnrBGDebJKIBdYKGF20vLCO8PY0h/DTA1uUHHwT5A1OTSVkl2DCJ/NVF
5e31kDsg2weGTULQGkVBUgybkAWJNvQSyeD6NlGBMHYKNU93NQuszab9U5rAO3z2
TpP6FSLXeEKPs2RSa7Bbc5QLjB/B0rqoHrnDTIXD9zFiA5aRdIELiZY4gQD5vc5F
AfMNE5CM5VM2+SBuvn2a7y2WuM+AynfOPL5RQFFe4ldEgoQQeWhFrhEqPn3rud8s
b4rmEWOj9cemq08UatV2pKIrrcgIuMULwCT3rFt0FOMIr6bVUpItrNvcjPi17Pdw
kZjNg7O0NCU0mYdMXsi2Jj0uRI6TxjuVWoQ2fQyoJc520auYn0C0diREWljBl1NG
MQ3nR71WEGxDGdfcw3tKm/g1GN7dkH4YvpbjPWjN6AyLkv/u7gGtyshyb8NgvlJb
xdteAKuAFjop7MftLF7MKshu4ODj7gdrjJVA329CSdjn4tCteX2Q6iKVUfcXpUMA
OjblRST9/callgQmbpj5pXrB4XLYZk+TDvhFpuTtEzTcKYCfem5CQ/vn3sXJ+iEH
EraATKvpQLlCqzKB14WqaOfISQhg/viie4ieRZHDdHLxuPRzisK8BipxWdQppQqW
g8pc2hZv6RgiW7FeEm/pNlpQaw48ifE3uvscqntmm7nP3GiE+xYEPdy/RgVrPe5W
YkaZdSY4Tb/bRKEAHUGX12CFSdifTgJxBVEQpwmFXHNRDEj6E48blDV6Mni/MioY
LJVWvXxEQyRuiIkCVhugs/nGk6TQOvGDnXq+bAXGcHZD43bZkypSLdVvMnkaHZ0H
dqqM5yfz7tRpNaPvwwPKPI6cnAWPq5IWBKHgo/FZ97imWzFLlRJRxquuKm94fScR
gaBHGD7XxTqSD2nhqEkGxBUmdHoKbEaMDLxRK4dvKP7ut0e40HzlCE5ofiUuCh9B
4RODmkZSr0jdtkgEeFqSor05oUaxpu51aYcMVishZq6F07wLS0Uzdn+EbcwfYGv0
T9hJaA9UZRj/cBOo81hfoqvxN8CkH8aQ9Nv3Xbr8+LR+mQmcMvluxlqtC9FciIyf
pxFixTlQtSPS6DH3taDfxD2aHggI/IY9TsEuIqp/VNRTiHLJ7VfTlL03/QaQZ1T/
N5u9zavvpoozoWnXcgM9GoyuE8Z149qgNi4gqcVjEh2EPJur+4QEaZm+mS+ows/4
AuOsDYJ6AJw6Qtw2G0qqDsbcz8EEkIZuxu6Tfb1rbI0tFyys4We3fGdePgdaEJCW
xufczFA8cgC7CBSJfSJx9Op05hMGSEtOgRLRrZJL7u4kAsQ9Zqamz8/2mM5YCO3E
zNN89k6b13fmcuXcN2bFacoQbrXJgA72EAinKEq1lyiB4q0LD5Kp4mM3Fia7gZqs
NGoP5pM61eXypNFU0Wlsq28odu86FxzXia05ataIehyidfGeWEzkDrZc4uwffymF
8Fc=
-----END ENCRYPTED PRIVATE KEY-----

[ 'openssl req -new -new -nodes -key rsa.key -config config.txt -passin pass:test' ]
-----BEGIN CERTIFICATE REQUEST-----
MIIDxTCCAq0CAQAwge0xCzAJBgNVBAYTAlVTMRIwEAYDVQQIDAlMb3Vpc2lhbmEx
EDAOBgNVBAcMB1NsaWRlbGwxDjAMBgNVBBEMBTcwNDU4MRkwFwYDVQQJDBAxMDAx
IEdhdXNlIEJsdmQuMQwwCgYDVQQKDANTTUgxCzAJBgNVBAsMAklUMR0wGwYDVQQD
DBRjZXJ0aWZpY2F0ZXRvb2xzLmNvbTEhMB8GA1UEAwwYd3d3LmNlcnRpZmljYXRl
dG9vbHMuY29tMTAwLgYJKoZIhvcNAQkBFiFseWFzLnNwaWVobGVyQHNsaWRlbGxt
ZW1vcmlhbC5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCe+OU/
TpicMHwfwUo185seGmmUprWQHTXsJ4a4AWSvmBTses8ObWdFEn/zqZhRchFMlp1a
3guyGmM/eSAO1Ie/tr2DVAPUH+w6OttucrSLtpyMcops3me6xW61xiZ8DpciP0EU
kjGWoxdC+ZOAV6o0sRpYIIv2OUfBb82W2PV2U8YBhvM65Ybw7xl+Wz2ufcxBABGb
fhQMqwtYtcCV93uaQ4KCZlQuk6leKq8DfI6VQ/vxuzV7KvLL9wYfX2u0++TvmyMC
MWVUlsYuyjJ8KlSx2BroyvzyzppKlDOdhUNdM3i2ln1X4W68PlFZxopjFoR9HL0i
ZbbnCv40JQMP83ArAgMBAAGggZEwgY4GCSqGSIb3DQEJDjGBgDB+MBIGA1UdEwEB
/wQIMAYBAf8CAQEwCwYDVR0PBAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjA5BgNVHREEMjAwghRjZXJ0aWZpY2F0ZXRvb2xzLmNvbYIYd3d3
LmNlcnRpZmljYXRldG9vbHMuY29tMA0GCSqGSIb3DQEBDQUAA4IBAQA6NHqm+zh4
H0whrVcAJ/udn5wY70L8sZgjsVBhWPdV4ZyMm2ZdfrHvkav64DsLW3K/5TjgB3oc
gvKI0ruCWCgsKSM9gmWyTxUuVPT6M/cL/qLQNr2h+UoSvvqcD/spwlMtY1FDgfHy
Q3FnUY7BBLFffbxgiJ/LTrvsE7RAvGtRRgYhR/pAl7P1XsD7Iqip1XfFHYRL++/o
6A0z+kkcZBT4QME2Bm9UmTbI7zDaNcfUJ1QI1oBfLosZ/Uj5d2cAHDc/gD5/u/Ep
vHPMCq0pwYXN/MTFWw7IKGuZ3L+zSgEg/kuvL3qOvpiacFfUvo5BcxXMkSupiBqc
JX0LCXd6RpV8
-----END CERTIFICATE REQUEST-----

[ req ]
default_md = sha512
prompt = no
req_extensions = req_ext
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
countryName = US
stateOrProvinceName = Louisiana
localityName = Slidell
postalCode = 70458
streetAddress = 1001 Gause Blvd.
organizationName = SMH
organizationalUnitName = IT
0.commonName = certificatetools.com
1.commonName = www.certificatetools.com
emailAddress = lyas.spiehler@slidellmemorial.org
[ req_ext ]
basicConstraints=critical,CA:true,pathlen:1
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=critical,serverAuth,clientAuth
subjectAltName = @alt_names
[ alt_names ]
DNS.0 = certificatetools.com
DNS.1 = www.certificatetools.com
```
Import an existing RSA private key with password test and generate a CSR using it.
```
const fs = require('fs');

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

fs.readFile('./test/rsa.key', function(err, contents) {
    openssl.importRSAPrivateKey(contents, 'test', function(err, key, cmd) {
		openssl.generateCSR(csroptions, key, 'test', function(err, csr, cmd) {
			if(err) {
				console.log(err);
			} else {	
				console.log(csr);
			}
				
		});
	});
});
```
Will return like this:
```
-----BEGIN CERTIFICATE REQUEST-----
MIIDxTCCAq0CAQAwge0xCzAJBgNVBAYTAlVTMRIwEAYDVQQIDAlMb3Vpc2lhbmEx
EDAOBgNVBAcMB1NsaWRlbGwxDjAMBgNVBBEMBTcwNDU4MRkwFwYDVQQJDBAxMDAx
IEdhdXNlIEJsdmQuMQwwCgYDVQQKDANTTUgxCzAJBgNVBAsMAklUMR0wGwYDVQQD
DBRjZXJ0aWZpY2F0ZXRvb2xzLmNvbTEhMB8GA1UEAwwYd3d3LmNlcnRpZmljYXRl
dG9vbHMuY29tMTAwLgYJKoZIhvcNAQkBFiFseWFzLnNwaWVobGVyQHNsaWRlbGxt
ZW1vcmlhbC5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCv69qN
xSN/piKKS44mVwgxAOCeSMS1qzmV+73O00zI9lzT5kGiKSmg3pDnzUoXTiLFJRWw
7IQBpRisLMwTZTH+xGNb9A4ViCLosgEC2skGe5pbF6rigTSQrJSl69mDjg/8Xm/I
Dnh2bCS1pjw+jhCSVfqSEFhxny8QXxnyTQWCakn1lfrDbbHHsh55hPN4aQ9vF9vC
V9RTVUfKoTrc8T5rsgyxZZq4rYxWuVatarS1L/v+YY2LObv8w/lidhxt8VkUGZOu
oZDEKLPPRVzh/8zcaYQlAXQLtwLiSK+npUrJbou9PLsSW0Rj7U5eTRatuQf9Z+Zm
vXS/Avf7y+0RZj4ZAgMBAAGggZEwgY4GCSqGSIb3DQEJDjGBgDB+MBIGA1UdEwEB
/wQIMAYBAf8CAQEwCwYDVR0PBAQDAgWgMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMB
BggrBgEFBQcDAjA5BgNVHREEMjAwghRjZXJ0aWZpY2F0ZXRvb2xzLmNvbYIYd3d3
LmNlcnRpZmljYXRldG9vbHMuY29tMA0GCSqGSIb3DQEBDQUAA4IBAQBW7oYzsYBI
yQKrGLj5qtJHqZutzflJYVwmevzdDBDtTJZsIiFENIlGqkzRxEQTLqISnC/jPR86
2N5m3cn7JGjwEQMGwKMJPxKmBbJu0WTl2n84dTnoJr16mTKaK/03w8uqLArW1pZH
ImKhA3S2GTyEpLbhX1eoQF35Wt1+G8JGf6JCH7a/Mj9KhlaPLFl8BImApyY9zR2l
DrJfTYMaUqzC77FnAecLvglXKPMEv9oKuABbab/RsCsSTV2/ikgXheGdcF7KIA3t
9qnu5s757nIDgIkJkpOFiI+Z5PFQlJJTOTU909cAFy9HapWTA8DN3t24vlSe1vXc
nI6qB6XsphQP
-----END CERTIFICATE REQUEST-----
```