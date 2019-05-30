const node_openssl = require('../index.js');
var fs = require('fs');

var options = {
	binpath: 'C:/Program Files/OpenVPN/bin/openssl.exe'
}

var openssl = new node_openssl(options);

var netcertoptions = {
	hostname: 'www.aol.com',
	port: 443,
	starttls: false,
	protocol: 'https'
}

function parseOCSPResponse(resp) {
	//console.log(resp);
	var ocspresp = {}
	let body = resp.split('OCSP Response Data:')[1].split('Signature Algorithm:')[0];
	let splitbody = body.split('\n');
	for(let i = 0; i <= splitbody.length - 1; i++) {
		if(splitbody[i].indexOf(':') >= 0) {
			let values = splitbody[i].split(':');
			if(values.length == 2) {
				ocspresp[values[0].trim(' ')] = values[1].trim(' ').replace('\r', '');
			} else if(values.length >= 3) {
				ocspresp[values[0].trim(' ')] = new Date(values.slice(1).join(':').trim(' ').replace('\r',''));
			} else {
				
			}
		}
	}
	return ocspresp;

}

/*openssl.getCertFromNetwork(netcertoptions, function(err, cert, cmd) {
	if(err) {
		console.log(err);
	} else {
		//console.log(cmd);
		openssl.getOCSPURI(cert[0], function(err, uri, cmd) {
			//console.log(err);
		//	console.log(cmd);
			//console.log(uri);
		//	console.log(cert);
		//	process.exit();
			let leaf = cert[0];
			let ca = cert.splice(1).join('\r\n') + '\r\n';
			openssl.queryOCSPServer(ca, leaf, uri, function(err, resp, cmd) {
				console.log(cmd);
				//console.log(parseOCSPResponse(resp));
				//console.log(cmd.ca);
				//console.log(cmd.cert);
				//console.log(cmd.command);
			});
		});
	}
});*/

/*openssl.tcpCheck('vfgdsdf.com', 443, function(err, result) {
	if(err) {
		console.log(err);
	} else {
		console.log(result);
	}
});*/

fs.readFile('./cert.cer', function(err, contents) {
	openssl.getIssuerURI(contents.toString(), function(err, uri, cmd) {
		console.log(uri);
		//console.log(cmd);
		openssl.downloadIssuer(uri, function(err, cert) {
			if(err) {
				console.log(err);
			} else {
				console.log(cert);
			}
		});
	});
});

/*fs.readFile('./GTSGIAG3.cer', function(err, contents) {
	openssl.convertDERtoPEM(contents, function(err, cert){
		console.log(cert);
	});
});*/
