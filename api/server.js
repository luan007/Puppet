const net = require("net");
const cluster = require("cluster");
const tls = require("tls");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const readline = require("readline");
const EventEmitter = require('events');
const util = require('util');

function to10(v) {
    if (v == true) return "1";
    if (v == false) return "0";
    if (v == undefined || v == null) return "0";
    if (v == "0") return "0";
    return '1';
}

function arr(v) {
    var txt = "";
    for (var i = 0; i < v.length; i++) {
        var j = sanitizeInput(v[i]).toString();
        j = j.replace(/\s/g, "");
        j = j.replace(/"/g, "");
        txt += j + " ";
    }
    return txt.trim();
}

var waitCb = {};

hub.on("cleanup", function (pack) {
    var i = waitCb[pack.uid];
    if (!i) return;
    var keys = Object.keys(i);
    for(var t = 0; t < keys.length; t++) {
        var key = keys[t];
        i[key]({
            out: "",
            err: "router reset"
        });
        delete i[key];
    }
});
hub.on("oncmdresult", function (pack) {
    var i = waitCb[pack.uid];
    if (!i || !pack.data[0] || !i[pack.data[0].id]) return;
    var id = pack.data[0].id;
    i[id](cmds_results[pack.uid][id]);
    delete i[id];
});
hub.on("oncmdresulterr", function (pack) {
    var i = waitCb[pack.uid];
    if (!i || !pack.data[0] || !i[pack.data[0].id]) return;
    var id = pack.data[0].id;
    i[id]({
        err: "R_FAIL, Server side Failure."
    });
    delete i[id];
});

function hookres(uid, id, cb, timeout) {

    var t;
    var q = function (res) {
        clearTimeout(t);
        cb(res);
    };

    t = setTimeout(() => {
        q({
            err: "Timed out"
        });
    }, timeout);

    if (!waitCb[uid]) {
        waitCb[uid] = {};
    }
    waitCb[uid][id] = q;
}

function sanitizeInput(val, noquote) {
    if(Array.isArray(val)) return val;
    // val = val; //`helloworld; &test; $.."%next sec | boom`;
    // val = `
    //     helloworld
    //     there u go
    // `
    if (!val) return "";
    val = val + "";
    result = val.replace(/(["$'\\])/g, "\\$1");
    result = val.replace(/(\r|\n)/g, "");
    if(!noquote){
        result = "\"" + result + "\"";
    // console.log(result);
    }
    return result;

}


function b_commit(detect, actions) {
    var conf = "";
    conf += "\nc=" + detect;
    for (var i = 0; i < actions.length; i++) {
        conf += '\n[[ ! -z "${c// }" ]] && ' + actions[i];
    }
    return conf;
}


function keyEqs(key, val) {
    key = sanitizeInput(key, true);
    val = sanitizeInput(val, true);
    return `
    result=$(${val} 2>/dev/null)
    echo "\\"${key}\\": \\"$result\\""
    `;
}

function keyArr(key, val) {
    key = sanitizeInput(key, true);
    val = sanitizeInput(val, true);
    return `
    result=$(uci -d '","' get ${val} 2>/dev/null)
    if [[ $result != "" ]]; then
        echo "\\"${key}\\": [\\"$result\\"]"
    else 
        echo "\\"${key}\\": []"
    fi
    `;
}

function beginConfSection(key) {
    key = sanitizeInput(key);
    return `
        echo "\\"${key}\\":{"
    `;
}

function endConfSection() {
    return `
        echo "},"
    `;
}

var translator = {
    default: {
        config: {
            ap: (c) => {
                var conf = "";
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'ssid':
                            if (v.length < 20 && v.length > 0) {
                                conf += '\nuci set wireless.@wifi-iface[1].ssid=' + v;
                            }
                            break;
                        case 'passwd':
                            if (v.length < 19 && v.length > 10) {
                                conf += '\nuci set wireless.@wifi-iface[1].key=' + v;
                                conf += "\nuci set wireless.@wifi-iface[1].encryption='psk2'";
                            } else if (v.length == 0) {
                                //no auth
                                conf += "\nuci set wireless.@wifi-iface[1].encryption='none'";
                            }
                            break;
                        case 'hidden':
                            conf += '\nuci set wireless.@wifi-iface[1].hidden=' + to10(v);
                            break;
                        case 'disabled':
                            conf += '\nuci set wireless.@wifi-iface[1].disabled=' + to10(v);
                            break;
                    }
                }
                if (conf.length == 0) return "";
                conf += b_commit('$(uci changes wireless)', [
                    'uci commit wireless',
                    'wifi'
                ]);
                return conf;
            },
            mesh: (c, apiOnly) => {
                if (!apiOnly) throw new Error("To ensure network topology, mesh Settings can only be accessible via dedicate API");
                var conf = "";
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'id':
                            if (v.length < 20 && v.length > 0) {
                                conf += '\nuci set wireless.@wifi-iface[0].ssid=' + v;
                            }
                            break;
                        case 'enc':
                            if (v.length < 20 && v.length > 9) {
                                conf += '\nuci set wireless.@wifi-iface[0].key=' + v;
                                conf += "\nuci set wireless.@wifi-iface[0].encryption='wep'";
                            } else if (v.length == 0) {
                                //no auth
                                conf += "\nuci set wireless.@wifi-iface[0].encryption='none'";
                            }
                            break;
                        case 'ip':
                            if (c["master"] && v.length > 0) {
                                conf += '\nuci set network.mesh.ipaddr=\'' + v + '\'';
                            }
                            break;
                        case 'disabled':
                            conf += '\nuci set wireless.@wifi-iface[0].disabled=' + to10(v);
                            break;
                        case 'master':
                            break;
                    }
                }
                if (conf.length == 0) return "";
                conf += b_commit('$(uci changes wireless)', [
                    'uci commit wireless',
                    'wifi'
                ]);
                conf += b_commit('$(uci changes network)', [
                    'uci commit network',
                    '/etc/init.d/network restart'
                ]);
                return conf;
            },
            socksProxy: (c) => {
                var conf = "";
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'enabled':
                            conf += '\nuci set redsocks.base.enabled=' + to10(v);
                            break;
                    }
                }
                if (conf.length == 0) return "";
                conf += b_commit('$(uci changes redsocks)', [
                    'uci commit redsocks',
                    '/etc/init.d/redsocks restart',
                    '/etc/init.d/firewall restart'
                ]);
                return conf;
            },
            wifidog: (c) => {
                var conf = "";
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'enabled':
                            conf += '\nuci set wifidog.wifidog.enabled=' + to10(v);
                            break;
                        case 'gateway_id':
                            if (v.length == 0) continue;
                            conf += '\nuci set wifidog.wifidog.gateway_id=' + v;
                            break;
                        case 'inactive_time':
                            //todo
                            if (v.length == 0) continue;
                            conf += '\nuci set wifidog.wifidog.client_timeout=' + v;
                            break;
                        // case 'blocklddist':
                        //     if (v.length == 0) continue;
                        //     conf += '\nuci set wifidog.wifidog.gateway_id=\'' + v + '\'';
                        //     break;
                        case 'trustedmac':
                            if (!Array.isArray(v)) continue;
                            v = arr(v);
                            conf += '\nuci_build_list wifidog.trustedmac.mac \"' + v + "\"";
                            break;
                        case 'domains':
                            if (!Array.isArray(v)) continue;
                            v = arr(v);
                            conf += '\nuci_build_list wifidog.rule_url.url \"' + v + "\"";
                            break;
                        case 'add_trustedmac':
                            if (!Array.isArray(v)) continue;
                            v = arr(v);
                            conf += '\nuci_add_to_list wifidog.trustedmac.mac \"' + v + "\"";
                            break;
                        case 'add_domains':
                            if (!Array.isArray(v)) continue;
                            v = arr(v);
                            conf += '\nuci_add_to_list wifidog.rule_url.url \"' + v + "\"";
                            break;
                        case 'del_trustedmac':
                            if (!Array.isArray(v)) continue;
                            v = arr(v);
                            conf += '\nuci_remove_from_list wifidog.trustedmac.mac \"' + v + "\"";
                            break;
                        case 'del_domains':
                            if (!Array.isArray(v)) continue;
                            v = arr(v);
                            conf += '\nuci_remove_from_list wifidog.rule_url.url \"' + v + "\"";
                            break;
                    }
                }
                if (conf.length == 0) return "";
                conf += b_commit('$(uci changes wifidog)', [
                    'uci commit wifidog',
                    '/etc/init.d/wifidog restart',
                    '/etc/init.d/firewall restart'
                ]);
                return conf;
            },
            iBeacon: (c) => {
                /*
                beacon.beacon=beacon
                beacon.beacon.enabled='1'
                beacon.beacon.uuid='FDA50693-A4E2-4FB1-AFCF-C6EB07647825'
                beacon.beacon.major='10'
                beacon.beacon.minor='7'
                beacon.beacon.power='c8'
                */
                var conf = "";
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'enabled':
                            conf += '\nuci set beacon.beacon.enabled=' + to10(v);
                            break;
                        case 'uuid':
                            conf += '\nuci set beacon.beacon.uuid=' + v;
                            break;
                        case 'major':
                            conf += '\nuci set beacon.beacon.major=' + v;
                            break;
                        case 'minor':
                            conf += '\nuci set beacon.beacon.minor=' + v;
                            break;
                        case 'power':
                            conf += '\nuci set beacon.beacon.power=' + v;
                            break;
                    }
                }
                if (conf.length == 0) return "";
                conf += b_commit('$(uci changes beacon)', [
                    'uci commit beacon',
                    '/etc/init.d/ibeacon restart',
                ]);
                return conf;
            }
        },
        config_read: {
            ap: (c) => {
                var conf = beginConfSection("ap");
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'ssid':
                            conf += keyEqs(k, "uci get wireless.@wifi-iface[1].ssid");
                            break;
                        case 'passwd':
                            conf += keyEqs(k, "uci set wireless.@wifi-iface[1].key");
                            break;
                        case 'hidden':
                            conf += keyEqs(k, "uci set wireless.@wifi-iface[1].hidden");
                            break;
                        case 'disabled':
                            conf += keyEqs(k, "uci set wireless.@wifi-iface[1].disabled");
                            break;
                    }
                }
                conf += endConfSection();
                return conf;
            },
            mesh: (c, apiOnly) => {
                var conf = beginConfSection("mesh");
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'id':
                            conf += keyEqs(k, "uci get wireless.@wifi-iface[0].ssid");
                            break;
                        case 'enc':
                            conf += keyEqs(k, "uci get wireless.@wifi-iface[0].key");
                            break;
                        case 'ip':
                            conf += keyEqs(k, "uci get network.mesh.ipaddr");
                            break;
                        case 'disabled':
                            conf += keyEqs(k, "uci get wireless.@wifi-iface[0].disabled");
                            break;
                        case 'master':
                            break;
                    }
                }
                conf += endConfSection();
                return conf;
            },
            socksProxy: (c) => {
                var conf = beginConfSection("socksProxy");
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'enabled':
                            conf += keyEqs(k, "uci get redsocks.base.enabled");
                            break;
                    }
                }
                conf += endConfSection();
                return conf;
            },
            wifidog: (c) => {
                var conf = beginConfSection("wifidog");
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'enabled':
                            conf += keyEqs(k, 'uci get wifidog.wifidog.enabled');
                            break;
                        case 'gateway_id':
                            conf += keyEqs(k, 'uci get wifidog.wifidog.gateway_id');
                            break;
                        case 'inactive_time':
                            conf += keyEqs(k, 'uci get wifidog.wifidog.client_timeout');
                            break;
                        case 'trustedmac':
                            conf += keyArr(k, 'wifidog.trustedmac.mac');
                            break;
                        case 'domains':
                            conf += keyArr(k, 'wifidog.rule_url.url');
                            break;
                    }
                }
                conf += endConfSection();
                return conf;
            },
            iBeacon: (c) => {
                /*
                beacon.beacon=beacon
                beacon.beacon.enabled='1'
                beacon.beacon.uuid='FDA50693-A4E2-4FB1-AFCF-C6EB07647825'
                beacon.beacon.major='10'
                beacon.beacon.minor='7'
                beacon.beacon.power='c8'
                */
                var conf = beginConfSection("iBeacon");
                for (var k in c) {
                    var v = sanitizeInput(c[k]);
                    switch (k) {
                        case 'enabled':
                            conf += keyEqs(k, 'uci get beacon.beacon.enabled');
                            break;
                        case 'uuid':
                            conf += keyEqs(k, 'uci get beacon.beacon.uuid');
                            break;
                        case 'major':
                            conf += keyEqs(k, 'uci get beacon.beacon.major');
                            break;
                        case 'minor':
                            conf += keyEqs(k, 'uci get beacon.beacon.minor');
                            break;
                        case 'power':
                            conf += keyEqs(k, 'uci get beacon.beacon.power');
                            break;
                    }
                }
                conf += endConfSection();
                return conf;
            }
        },
        cmds: {
            transfer: (opts, auth) => {
                if (!auth) throw new Error("Not authorized");
                return "echo \"" + new Buffer(opts.content).toString("base64") + "\" > '/tmp/download'\nbase64 -d '/tmp/download' > \"" + sanitizeInput(opts.path) + "\"";;
            },
            download: (opts, auth) => {
                if (!auth) throw new Error("Not authorized");
                return "\nwget -O " + sanitizeInput(opts.file) + " " + sanitizeInput(opts.location) +
                    "\ntmp=($(md5sum " + sanitizeInput(opts.file) + "))" +
                    "\necho \"{ 'md5' : '$tmp', 'url' : '" + sanitizeInput(opts.location) + "' }\"";
            },
            transfer_portal: (opts) => {
                return "\n. /etc/edge/util.sh\ndownload " + sanitizeInput(opts.md5) + " " + sanitizeInput(opts.url);
            },
            transfer_portal_status: (opts) => {
                return "\n. /etc/edge/util.sh\ndownload_status";
            },
            reboot: (opts) => {
                //nowait - just go..
                return ['\nreboot', true];
            },
            sysupgrade: (opts, auth) => {
                if (!auth) throw new Error("Not authorized");
                return '\nsysupgrade ' + sanitizeInput(opts.file);
            },
            netstatus: (opts) => {
                return `
                echo "{"
                tmp=$(ubus -S call network.interface.mesh status)
                [[ ! -z "\${tmp// }" ]] && echo "\\"mesh\\": $tmp,"
                tmp=$(ubus -S call network.interface.lan status)
                [[ ! -z "\${tmp// }" ]] && echo "\\"lan\\": $tmp,"
                tmp=$(ubus -S call network.interface.wan status)
                [[ ! -z "\${tmp// }" ]] && echo "\\"wan\\": $tmp"
                echo "}"
                `
            },
            wifi: (opts) => {
                return `
                . /etc/edge/util.sh
                echo "{"
                tmp=\$(wlaninfo_tojson_type IBSS)
                [[ ! -z "\${tmp// }" ]] && echo "\\"mesh\\": $tmp,"
                tmp=\$(wlaninfo_tojson_type AP)
                [[ ! -z "\${tmp// }" ]] && echo "\\"ap\\": $tmp"
                echo "}"
                `;
            },
            clients: (opts) => {
                return `
                . /etc/edge/util.sh
                AP=$(find_wlan_w_mode "AP")
                ubus -S call hostapd.$AP get_clients
                `
            },
            meshdump: (opts) => {
                return `
                . /etc/edge/util.sh
                stadump_tojson_type IBSS
                `
            },
            clientdump: (opts) => {
                return `
                . /etc/edge/util.sh
                stadump_tojson_type AP
                `
            },
            speedtest: (opts) => {
                //todo
            },
            kick: (opts) => {
                //ban
                opts.ban = opts.ban === undefined ? 60 : (opts.ban + '');
                return `
                . /etc/edge/util.sh
                AP=$(find_wlan_w_mode "AP")
                ubus call hostapd.$AP del_client '{"addr": ${sanitizeInput(opts.mac)}, "reason": 1, "deauth": True, "ban_time": ${sanitizeInput(opts.ban)} }'
                `
            },
            //http://stackoverflow.com/questions/17809912/parsing-iw-wlan0-scan-output
            collectSurrounding: (opts, auth) => {
                //BSS,CHANNEL,SIGNAL,LAST SEEN,SSID
                if (!auth) throw new Error("Not authorized");
                return `
                . /etc/edge/util.sh
                nearby wlan0
                `
            },
        }
    }
};


function translate(conf, translator) {
    if (!translator || !translate.config) return "";
    var conf = "";
    for (var i in conf) {
        if (translator.config[i]) {
            conf += translator.config(i);
        }
    }
    console.log(conf);
    return conf;
}

function getBoard(uid) {
    return clients[uid].hwtype ? translator[clients[uid]] : translator.default;
}

function toUID(pid) {
    if (!pid) return undefined;
    return uid_client[pid];
}

var configs = {};

//load all conf
var allfiles = fs.readdirSync(__dirname + "/routers");
for (var i = 0; i < allfiles.length; i++) {
    try {
        console.log(">C - " + allfiles[i]);
        configs[allfiles[i]] = JSON.parse(fs.readFileSync(__dirname + "/routers/" + allfiles[i]).toString("utf8"));
    } catch (e) {
        console.log("xx - " + allfiles[i]);
        console.log(e);
    }
}


function saveRouterConfig(id) {
    if (configs[id]) {
        fs.writeFile(__dirname + "/routers/" + id, JSON.stringify(configs[id]));
    }
}


function buildServer(owner, auth) {

    function routerValid(uid) {
        return uid && clients[uid] && clients[uid].state > 1 && clients[uid].id && clients[uid].id.own == owner && clients[uid].uid;
    }

    var api = express();
    var http = require('http').Server(api);
    // var io = require('socket.io')(http);
    var bodyParser = require('body-parser');
    var serveStatic = require('serve-static');

    // parse application/x-www-form-urlencoded 
    //api.use(bodyParser.urlencoded({ extended: false }))

    // parse application/json 
    api.use(bodyParser.json());

    api.post("/router/:id/status", (req, res) => {
        var id = toUID(req.params['id']);
        if (!routerValid(id)) {
            res.status(200).json({
                "result": 0
            });
        } else {
            res.status(200).json({
                "result": 1
            });
        }
    });

    api.post("/router/:id/network", (req, res) => {
        var id = toUID(req.params['id']);
        if (!routerValid(id)) {
            return res.status(404).json({
                id: id,
                error: "Router Not Found / Offline"
            });
        }
        var gid = req.body.network;
        var skipresult = req.body.skipresult;
        if (!gid || gid.indexOf(":") >= 0) {
            return res.status(404).json({
                id: id,
                network: gid,
                error: "Null input ({network: null}) / Illegal Character"
            });
        }
        var board = getBoard(id);

        var c = board.cmds.transfer({
            content: gid,
            path: "/etc/edge/configs/group"
        }, true);

        var rand = sendCommand(id, c);
        if (!rand) {
            //crap happened..
            return res.status(400).json({
                id: id,
                result: 'Error sending config - Client not in good state'
            });
        }
        if (skipresult) {
            return res.status(200).json({
                id: id,
                result: 'sent'
            });
        } else {
            //wait till timeout.
            hookres(id, rand, (result) => {
                result.id = rand;
                if (!result.out && result.err) {
                    res.status(400).json(result);
                } else {
                    res.status(200).json(result);
                }
            }, 1000 * 60);
        }

    });

    api.post("/router/:id/config_state", (req, res) => {

        var uid = req.params['id'];
        var id = toUID(req.params['id']);

        if (!routerValid(id)) {
            return res.status(404).json({
                id: id,
                error: "Router Not Found / Offline"
            });
        }

        if (!req.body) {
            return res.status(404).json({
                id: id,
                error: "Missing Requesting Config Items (body)"
            });
        }
        var board = getBoard(id);
        var conf = `
        . /etc/edge/util.sh
        echo {
        `;
        for (var i in req.body) {
            if (!board.config_read[i]) {
                return res.status(404).json({
                    id: id,
                    key: i,
                    error: "Config Node does not exist on target hardware"
                });
            }
            try {
                conf += board.config_read[i](req.body[i], false);
            } catch (e) {
                console.log(e);
                console.log(e.stack);
                return res.status(400).json({
                    id: id,
                    key: i,
                    error: e
                });
            }
        }

        conf += `
            echo " \\"valid\\": 1 }"
        `;

        var rand = sendCommand(id, conf);
        if (!rand) {
            //crap happened..
            return res.status(400).json({
                id: id,
                result: 'Error requesting state - Client not in good state'
            });
        }

        hookres(id, rand, (result) => {
            result.id = rand;
            if (!result.out && result.err) {
                res.status(400).json(result);
            } else {
                res.status(200).json(result);
            }
        }, 1000 * 60);

    });

    api.post("/router/:id/config", function (req, res) {
        var uid = req.params['id'];
        var id = toUID(req.params['id']);

        if (!routerValid(id)) {
            return res.status(404).json({
                id: id,
                error: "Router Not Found / Offline"
            });
        }
        //offline config - tbd
        if (!req.body) {
            return res.status(404).json({
                id: id,
                error: "Missing Config (body)"
            });
        }
        var skipresult = req.body.skipresult;
        delete req.body.skipresult;
        var board = getBoard(id);
        var conf = ". /etc/edge/util.sh\n";
        for (var i in req.body) {
            if (!board.config[i]) {
                return res.status(404).json({
                    id: id,
                    key: i,
                    error: "Config Node does not exist on target hardware"
                });
            }
            try {
                conf += board.config[i](req.body[i], false);
            } catch (e) {
                console.log(e);
                console.log(e.stack);
                return res.status(400).json({
                    id: id,
                    key: i,
                    error: e
                });
            }
        }

        //save it for future

        var rand = sendCommand(id, conf);
        if (!rand) {
            //crap happened..
            return res.status(400).json({
                id: id,
                result: 'Error sending config - Client not in good state'
            });
        }

        if (!configs[uid]) {
            configs[uid] = {};
        }
        for (var i in req.body) {
            if (!configs[uid][i]) {
                configs[uid][i] = {};
            }
            for (var k in req.body[i]) {
                configs[uid][i][k] = req.body[i][k];
            }
        }
        saveRouterConfig(uid);

        if (skipresult) {
            return res.status(200).json({
                id: id,
                result: 'sent'
            });
        } else {
            //wait till timeout.
            hookres(id, rand, (result) => {
                result.id = rand;
                if (!result.out && result.err) {
                    res.status(400).json(result);
                } else {
                    res.status(200).json(result);
                }
            }, 1000 * 60);
        }
    });

    api.get("/router/:id", function (req, res) {
        var id = toUID(req.params['id']);
        if (!routerValid(id)) {
            return res.status(404).json({
                id: id,
                error: "Router Not Found / Offline"
            });
        }
        res.status(200).json(clients[id]);
    });

    api.delete("/router/:id", function (req, res) {
        var id = toUID(req.params['id']);
        if (!routerValid(id)) {
            return res.status(404).json({
                id: id,
                error: "Router Not Found / Offline"
            });
        }
        sockets[id].end();
        res.status(200).json({
            id: id,
            result: 'done'
        });
    });

    api.get("/routers", (req, res) => {
        //online only :)
        var dt = {};
        for (var i in clients) {
            if (routerValid(i)) {
                dt[clients[i].uid] = clients[i];
            }
        }
        res.status(200).json(dt);
    });

    api.post("/router/:id/:cmd", function (req, res) {
        var id = toUID(req.params['id']);
        if (!routerValid(id)) {
            return res.status(404).json({
                id: id,
                error: "Router Not Found / Offline"
            });
        }
        //build cmd?
        var cmd = req.params['cmd'];
        var board = getBoard(id);
        if (!board.cmds[cmd]) {
            return res.status(404).json({
                id: id,
                cmd: cmd,
                error: "Command for Router - Not Found"
            });
        }
        if (!req.body) {
            return res.status(400).json({
                id: id,
                cmd: cmd,
                error: "Empty Param?, expect at least {}"
            });
        }
        var c = board.cmds[cmd](req.body, auth);
        var out = c;
        var skipresult = req.body.skipresult;
        if (Array.isArray(c)) {
            out = c[0];
            skipresult = c[1];
        }
        console.log("Converted UID " + id);
        var rand = sendCommand(id, out);
        if (!rand) {
            //crap happened..
            return res.status(400).json({
                id: id,
                cmd: cmd,
                result: 'Error sending cmd - Client not in good state'
            });
        }
        if (skipresult) {
            res.status(200).json({
                id: id,
                cmd: cmd,
                result: 'sent'
            });
        } else {
            //wait till timeout.
            hookres(id, rand, (result) => {
                result.id = rand;
                result.cmd = cmd;
                if (!result.out && result.err) {
                    res.status(400).json(result);
                } else {
                    res.status(200).json(result);
                }
            }, 1000 * 60);
        }
    });

    api.get("/network/:id", (req, res) => {
        var id = req.params['id'];
        var dt = {};
        for (var i in clients) {
            if (routerValid(i) && clients[i].id.gid == id) {
                dt[clients[i].uid] = clients[i];
            }
        }
        res.status(200).json(dt);
    });

    // api.post("/network/:id/master", (req, res) => {
    //     var id = req.params['id'];
    //     var dt = {};
    //     for (var i in clients) {
    //         if (routerValid(i) && clients[i].id.gid == id) {
    //             dt[i] = clients[i];
    //         }
    //     }
    //     res.status(200).json(dt);
    // });
    return api;
}

module.exports.build = buildServer;