var fs = require('fs')
var net = require('net');
var http = require('http');
var https = require('https');
var crypto = require('crypto');
var yaml = require('js-yaml');
var xml2js = require('xml2js');
var request = require('request')
var url = require('url')
var querystring = require('querystring');
var crypto = require('crypto')
var Cookies = require('cookies')
var redis = require('redis')
var redis_client = redis.createClient()

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
var portal_hosts

function load_config() {
    config = yaml.safeLoad(fs.readFileSync(config_path));

    config.ssl.forEach(function(entry) {
        entry.key = fs.readFileSync(entry.key);
        entry.cert = fs.readFileSync(entry.cert);
    })

    portal_hosts = {}

    config.extranet.forEach(function(entry) {
        portal_hosts[entry.portal_host] = entry
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

function check_cookie(cookies, addr, cb) {
    var token = cookies.__extranet_auth
    get_session(token, function(data) {
        cb('ok')
    }, function() {
        cb('missing')
    })
}

function redirect_to_portal(cookies, host, req, res) {
    var conf = host_match(config.extranet, host)
    if(!conf) {
        res.statusCode = 500;
        res.end('missing extranet portal');
        return;
    }
    var proto = req.connection.encrypted ? 'https' : 'http'
    var next_url = proto + '://' + req.headers.host + req.url;

    crypto.randomBytes(32, function(ex, buf) {
        var token = cookies.__extranet_token
        if(!token) token = buf.toString('hex');

        res.writeHead(303, {
            'Location': conf.cas_url + '/login?service='
                + encodeURIComponent(
                    'https://' +
                        conf.portal_host +
                        '/?next=' + encodeURIComponent(next_url) +
                        '&token=' + token),
            'Set-Cookie': '__extranet_token='
                + token + '; domain=' + conf.host.slice(1)
                + '; secure; httponly'
        });
        res.end('redirect')
    })
}

function service_validate(host, ticket, service, cb, errcb) {
    var conf = host_match(config.extranet, host)
    var url = conf.cas_url + '/serviceValidate' +
        '?ticket=' + encodeURIComponent(ticket) +
        '&service=' + encodeURIComponent(service);

    console.log(url)
    request(url, function(error, response, body) {
        console.log('response', body)
        if(error || response.statusCode != 200)
            return errcb()

        xml2js.Parser().parseString(body, function(err, result) {
            if(err) return errcb()
            var r = result['cas:serviceResponse']
            if(r['cas:authenticationFailure'])
                return errcb()

            console.log(r['cas:user'])
            cb('none')
        });
    })
}

var sessions = {}

function register_session(token, data) {
    redis_client.hset('extranet_session', token,
                      JSON.stringify(data))
}

function get_session(token, cb, errcb) {
    redis_client.hget('extranet_session', token,
                      function(err, data) {
                          if(data)
                              cb(JSON.parse(data))
                          else
                              errcb()
                      })
}

function handle_portal(cookies, req, res, conf) {
    var p = url.parse(req.url)
    var query = querystring.parse(p.query)
    if(p.pathname != '/') {
        res.writeHead(404, {});
        res.end('not found');
        return;
    }

    if(cookies.__extranet_token != query.token) {
        res.writeHead(403, {});
        res.end('bad token');
        return;
    }

    service_validate(
        conf.portal_host,
        query.ticket,
        'https://' + conf.portal_host + '/?' +
            querystring.stringify({next: query.next, token: query.token}),
        function(additional_data) {
            crypto.randomBytes(32, function(ex, buf) {
                var token = buf.toString('hex');
                register_session(token, additional_data)

                res.writeHead(303, {
                    'Location': query.next,
                    'Set-cookie': '__extranet_auth='
                    + token + '; domain=' + conf.host.slice(1)
                    + '; secure; httponly'
                });
                res.end('redirect');
                return;
            });

            return;
        },
        function() {
            res.writeHead(500, {});
            res.end('error');
        })
}

function get_cookies(cookie_header) {
    // http://stackoverflow.com/questions/4003823/javascript-getcookie-functions/4004010#4004010
    var c = cookie_header, v = 0, cookies = {};
    if(!c) return {}
    if (c.match(/^\s*\$Version=(?:"1"|1);\s*(.*)/)) {
        c = RegExp.$1;
        v = 1;
    }
    if (v === 0) {
        c.split(/[,;]/).map(function(cookie) {
            var parts = cookie.split(/=/, 2),
                name = decodeURIComponent(parts[0].trimLeft()),
                value = parts.length > 1 ? decodeURIComponent(parts[1].trimRight()) : null;
            cookies[name] = value;
        });
    } else {
        c.match(/(?:^|\s+)([!#$%&'*+\-.0-9A-Z^`a-z|~]+)=([!#$%&'*+\-.0-9A-Z^`a-z|~]*|"(?:[\x20-\x7E\x80\xFF]|\\[\x00-\x7F])*")(?=\s*[,;]|$)/g).map(function($0, $1) {
            var name = $0,
                value = $1.charAt(0) === '"'
                          ? $1.substr(1, -1).replace(/\\(.)/g, "$1")
                          : $1;
            cookies[name] = value;
        });
    }
    return cookies;
}

function filter_cookies(cookies) {
    var cookie_str = '';
    for(var name in cookies) {
        if(!/^__extranet_(.*)/.test(name))
            cookie_str += name + '=' + cookies[name] + '; ';
    }
    cookie_str = cookie_str.slice(0, cookie_str.length - 2)
    return cookie_str;
}

function server_callback(req, res) {
    var host = req.headers.host;
    var respond, respond_error;

    var cookies = get_cookies(req.headers.cookie);
    req.headers.cookie = filter_cookies(cookies);

    if(portal_hosts[host]) {
        return handle_portal(cookies, req, res, portal_hosts[host])
    }

    get_addr_for(host, respond = function(addr) {
        var remote_ip = process_ip(req.connection.remoteAddress);
        console.log(remote_ip, req.method, host, req.url,
                   '->', addr.target_host, addr.target_port);

        if(!req.connection.encrypted) {
            if(addr.protect || addr.sslonly) {
                res.writeHead(301, {
                    'Location': 'https://' + req.headers.host +
                        req.url
                });
                res.end('redirect to ssl');
                return;
            }
        }

        function cb(status) {
            if(status == 'error') {
                return respond_error();
            }

            if(status == 'missing') {
                return redirect_to_portal(cookies, host, req, res);
            }

            var proxy_request = http.request({
                hostname: addr.target_host,
                port: addr.target_port,
                path: req.url,
                method: req.method,
                headers: req.headers});

            req.pipe(proxy_request);

            req.headers['X-Forwarded-For'] = remote_ip;

            proxy_request.on('response', function(proxy_response) {
                proxy_response.pipe(res);
                res.writeHead(proxy_response.statusCode, proxy_response.headers);
            })

            proxy_request.on('error', function(e) {
                console.log('problem with request: ' + e.message);
                res.statusCode = 502;
                res.end(e.message);
            });
        }

        if(addr.protect) {
            check_cookie(cookies, addr, cb);
        } else {
            cb('ok');
        }

    }, respond_error = function() {
        res.statusCode = 403;
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
    if(pattern[0] == '*' && val.slice(val.length - pattern.length + 1) == pattern.slice(1))
       return true;

    return false;
}

function host_match(conf, host) {
    for(var i=0; i < conf.length; i ++) {
        var entry = conf[i]
        if(entry.host && star_match(entry.host, host))
            return entry;
        if(entry.hosts)
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
