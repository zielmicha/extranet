var fs = require('fs')
var net = require('net');
var http = require('http');
var https = require('https');
var crypto = require('crypto');
var yaml = require('js-yaml');
var parseString = require('xml2js').parseString;

var Inotify = require('inotify').Inotify;
var inotify = new Inotify();

var config_path = 'config.yaml'

inotify.addWatch({
    path: config_path,
    watch_for: Inotify.IN_MODIFY,
    callback: function() {
        try {
            load_config()
        } catch(ex) {
            console.log(ex)
        }
    }
})

var config

function load_config() {
    config = yaml.safeLoad(fs.readFileSync(config_path));

    config.ssl.forEach(function(entry) {
        entry.key = fs.readFileSync(entry.key);
        entry.cert = fs.readFileSync(entry.cert);
    })
    console.log("loaded config")
}

load_config()

function get_addr_for(host, ok, error) {
    var result = host_match(config.proxy, host);
    if(result)
        ok(result);
    else
        error(result);
}

function process_ip(ip) {
    if(/^::ffff:[^:]+$/.test(ip)) {
        // normalize ipv6 form of ipv4 address to ipv4 address
        ip = ip.slice(7);
    }
    return ip;
}

function server_callback(req, res) {
    var host = req.headers.host;
    var respond;
    get_addr_for(host, respond = function(addr) {
        var remote_ip = req.connection.remoteAddress;
        console.log(remote_ip, req.method, host, req.url,
                   '->', addr.target_host, addr.target_port);

        var remote_addr = process_ip(req.connection.remoteAddress)

        var proxy_request = http.request({
            hostname: addr.target_host,
            port: addr.target_port,
            path: req.url,
            method: req.method,
            headers: req.headers});

        req.pipe(proxy_request);

        req.headers['X-Forwarded-For'] = remote_addr;

        proxy_request.on('response', function(proxy_response) {
            proxy_response.pipe(res);
            res.writeHead(proxy_response.statusCode, proxy_response.headers);
        })

        proxy_request.on('error', function(e) {
            console.log('problem with request: ' + e.message);
            res.statusCode = 502;
            res.end(e.message);
        });
    }, function() {
        res.statusCode = 502;
        res.end('no such host');
    })
}

function sni_callback(host, cb) {
    var ssl = host_match(config.ssl, host);
    if(!ssl) ssl = host_match(config.ssl, 'default')
    var cred = crypto.createCredentials({key: ssl.key, cert: ssl.cert});
    //cb(null, cred.context); - for newer Node
    return cred.context
}

function star_match(pattern, val) {
    if(pattern == val)
        return true;
    if(pattern[0] == '*' && val.slice(0, pattern.length - 1) == pattern.slice(1))
       return true;
    return false;
}

function host_match(conf, host) {
    for(var i=0; i < conf.length; i ++) {
        var entry = conf[i]
        if(entry.host && star_match(entry.host, host))
            return entry;
        for(var j=0; j < entry.hosts.length; j++)
            if(star_match(entry.hosts[j], host))
               return entry;
    }
}

var https_options = host_match(config.ssl, 'default')
if(!https_options) {
    throw("SSL config not defined for host default")
}
https_options['SNICallback'] = sni_callback;

var https_server = https.createServer(https_options, server_callback);
https_server.listen(443, '::', null);

var http_server = http.createServer(server_callback);

http_server.listen(80, '::', null, function() {
    try {
        process.setgid('daemon');
        process.setuid('proxy');
    } catch (err) {
        console.log('setuid/setgid failed');
        process.exit(1);
    }
});
