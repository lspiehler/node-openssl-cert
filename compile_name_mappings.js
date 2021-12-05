const https = require('https');

var httpRequest = function(params, callback) {
    const req = https.request(params.options, res => {
        var resp = [];

        res.on('data', function(data) {
            resp.push(data);
        });

        res.on('end', function() {
            callback(false, {statusCode: res.statusCode, options: params.options, headers: res.headers, body: Buffer.concat(resp).toString()});
        });
    })

    req.on('error', function(err) {
        //console.log(err);
        callback(false, {statusCode: false, options: params.options, headers: false, body: JSON.stringify(err)});
    })

    if(params.options.method=='POST') {
        req.write(JSON.stringify(params.body));
    }

    req.end()
}

let options = {
    host: 'raw.githubusercontent.com',
    path: '/openssl/openssl/OpenSSL_1_1_1-stable/crypto/objects/objects.txt',
    method: 'GET'
}

//stage old names
var oids = {
    "Microsoft Universal Principal Name": "msUPN",
    "Microsoft Smartcardlogin": "msSmartcardLogin"
}

httpRequest({options: options}, function(err, resp) {
    if(err) {
        console.error(err);
    } else {
        let lines = resp.body.split('\n');
        for(let i = 0; i <= lines.length - 1; i++) {
            if(lines[i] != '' && lines[i].charAt(0)!='#' && lines[i].charAt(0)!='!') {
                //console.log(lines[i].charAt(0);
                let line = lines[i].split(':');
                let key;
                let value;
                //console.log(lines[i]);
                //console.log(line);
                if(line.length == 3) {
                    key = line[2].trim();
                    value = line[1].trim();
                } else {
                    key = line[1].trim();
                    value = line[1].trim();
                }
                if(value != '') {
                    oids[key] = value;
                } else {
                    oids[key] = key;
                }
            }
        }
        console.log('module.exports = ' + JSON.stringify(oids, null, 2));
        let keys = Object.keys(oids);
        console.error('Returned ' + keys.length + ' name mappings');
    }
});