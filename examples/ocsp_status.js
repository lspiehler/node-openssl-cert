const node_openssl = require('../index.js');
var fs = require('fs');

var options = {
	binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
}

var openssl = new node_openssl(options);

var netcertoptions = {
	hostname: 'notjustnetworks.com',
	port: 443,
	starttls: false,
	protocol: 'https'
}

openssl.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
	if(err) console.log(err);
	//console.log(cmd);
	openssl.getOCSPURI(cert[0], function(err, uri, cmd) {
		//console.log(err);
		//console.log(cmd);
		//console.log(uri);
		let leaf = cert[0];
		let ca = cert.splice(1).join('\r\n');
		openssl.queryOCSPServer(ca, leaf, uri, function(err, resp, cmd) {
			console.log(resp);
		});
	});
});

/*fs.readFile('./google.crt', function(err, contents) {
	openssl.getIssuerURI(contents.toString(), function(err, uri, cmd) {
		console.log(uri);
		openssl.downloadIssuer(uri, function(err, cert) {
			if(err) {
				console.log(err);
			} else {
				console.log(cert);
			}
		});
	});
});*/

/*fs.readFile('./GTSGIAG3.cer', function(err, contents) {
	openssl.convertDERtoPEM(contents, function(err, cert){
		console.log(cert);
	});
});*/