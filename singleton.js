const net = require("net");
const cluster = require("cluster");
const tls = require("tls");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const readline = require("readline");
const keepalive = require('net-keepalive');
var CA_FailSafe = false;
var REPAIR_MODE = false;
const EventEmitter = require('events');
const util = require('util');

function eventHub() {
  EventEmitter.call(this);
}
util.inherits(eventHub, EventEmitter);

var hub = new eventHub();
hub.emit('boot');

global.hub = hub;


function emit(event, _uid, data){
    if(!io) return;
    var d = {
        uid: _uid,
        data: data
    };
    io.emit(event, d);
    var j = {
        key: event,
        pack: d
    };
    io.emit("event", j);
    hub.emit(event, d);
    hub.emit("event", j);
}

hub.on("error", function(){
    //handled
});


function md5(str) {
    var md5sum = crypto.createHash('md5');
    md5sum.update(str);
    str = md5sum.digest('hex');
    return str;
}

const constants = require("constants");
const uuid = require("uuid");
const SAFE_MEM = 1024 * 1024 * 1024 * 3;
const DENYCLOCK = 1000 * 10;
const MAC_DEAD = 1000 * 60; //2 min
const CMD_CLEAN = 1000 * 120; //2 min
const CMD_REFETCH = 1000 * 5; //5 sec
const FETCH_ON_EXEC = true;
const BABYSIT_INTERVAL = 5000;
const LAZYLOAD_SIZE = 10240; //10kb


var clients = {};
var uid_client = {};
var cmds = {};
var cmds_results = {};
var cmd_sorts = {};
var sockets = {};

global.clients = clients;
global.cmds = cmds;
global.cmds_results = cmds_results;
global.sockets = sockets;
global.uid_client = uid_client;
global.cmd_sorts = cmd_sorts;
// global.socket

//load all CA
var CAList = [];
var ca = fs.readdirSync("keys/clients");
for (var i = 0; i < ca.length; i++) {
    if (ca[i].toLowerCase().endsWith('.crt')) {
        CAList.push(fs.readFileSync("keys/clients/" + ca[i]));
    }
}

//load all PEM
var PKList = [];
var pk = fs.readdirSync("keys/doublecheck");
for (var i = 0; i < pk.length; i++) {
    if (pk[i].toLowerCase().endsWith('.pem')) {
        PKList.push(//{
            // key:
            fs.readFileSync("keys/doublecheck/" + pk[i]).toString("utf8")
        // ,
        // padding: constants.RSA_PKCS1_PADDING
        // });
            );
    }
}


var options = {
    key: fs.readFileSync("keys/server.key", "utf8"),
    cert: fs.readFileSync("keys/server.crt", "utf8"),
    requestCert: true,
    rejectUnauthorized: true,
    ca: CAList
}

global.sendCommand = function sendCommand(uid, cmd) {
    // cmd = cmd.replace(/\\/g, '\\\\');
    
    var raw = cmd;
    cmd = new Buffer(raw).toString("base64");
    var socket = sockets[uid];
    var client = clients[uid];

    if (!socket || !client) {
        console.log("CMD ABORTED ! CLIENT DOES NOT EXIST:", uid);
        return;
    }
    if (client.state < 2) {
        console.log("CMD ABORTED ! CLIENT NO AUTH", uid);
        return;
    }
    var rand = uuid.v4();
    console.log("CMD", uid, raw, " > ", rand);
    cmds[uid][rand] = {
        id: rand,
        state: 0,
        cmd: raw,
        sanitized: cmd,
        time: Date.now(),
        sort: cmd_sorts[uid].length
    };
    cmds_results[uid][rand] = {};
    cmd_sorts[uid].push(rand);
    
    emit('sendcmd', uid, cmds[uid][rand]);
    
    socket.write('cmd ' + rand + ' "' + cmd + '"\n');
    return rand;
}

global.fetch = function fetch(uid, id) {
    var socket = sockets[uid];
    var client = clients[uid];
    var cmd = cmds[uid];
    if (!socket) {
        console.log("FETCH ABORTED ! CLIENT DOES NOT EXIST:", uid);
        return;
    }
    if (client.state < 2) {
        console.log("FETCH ABORTED ! CLIENT NO AUTH", uid);
        return;
    }

    if (!cmd[id]) {
        console.log("FETCH ABORTED ! CMD DOES NOT EXIST", uid, id);
        return;
    }

    if (cmd[id].state < 2) {
        console.log("FETCH ABORTED ! CMD NOT READY", uid, id);
        return;
    }

    cmd[id].rtime = Date.now();

    console.log("FETCH", uid, " < ", id);
    emit('fetch', uid, cmd[id]);
    socket.write("fetch " + id + "\n");
}

function cleanUp(uid) {
    if (clients[uid]) {
        var socket = sockets[uid];
        clearTimeout(socket.denialClock);
        // try{
        //     socket.end();
        // }catch(e){
        //     console.log("!ERR! Connection Failed to end - ", e);
        // }
        try{
            delete uid_client[clients[uid].id.uid];
        } catch(e) {
            //anyway..
        }
        delete clients[uid];
        delete sockets[uid];
        delete cmds[uid];
        delete cmd_sorts[uid];
        delete cmds_results[uid];
        // clients[uid] = undefined;
        socket.removeAllListeners();
        socket.uid = undefined;
        emit('cleanup', uid);
    }
}

function error(uid, content) {
    if (!sockets[uid]) return;
    console.log("!ERR!", uid, content);
    emit('error', uid, content);
    sockets[uid].end();
}

function init(uid, param) {
    console.log("INIT", uid, param);
    var client = clients[uid];
    var socket = sockets[uid];
    if (client.state == 0) {
        var dt = param.split(":::");
        if (dt.length < 4 && !REPAIR_MODE) {
            return error(uid, "Bad Init - ", param);
        }
        
        if(dt.length >= 4) {
            dt[1] = (dt[1].length > 0) ? dt[1] : undefined;
            client.id = {
                hardver: dt[0],
                uid: dt[1],
                did: dt[2],
                nid: dt[3],
                gid: dt[4] || "",
                own: dt[5] || "",
                mac: dt[6] || ""
            };
        } else {
            client.id = {
                    hardver: '-BROKEN-REPAIR-',
                    uid: undefined,
                    did: 'REPAIR_' + uuid.v4().toString(),
                    nid: 'REPAIR_' + uuid.v4().toString(),
                    gid: "",
                    own: "",
                    mac: ""
            };
        }
        client.uid = client.id.uid;
        if(client.id.uid) {
            uid_client[client.id.uid] = uid;
        }
        emit('oninit', uid, client);
        socket.write(client.auth.challenge + "\n");
        client.state = 1; //await result
    } else {
        return error(uid, "State Error - Init at ", client.state);
    }
}

function running(uid, param) {
    console.log("running", param);
    var socket = sockets[uid];
    var client = clients[uid];
    var cmd = cmds[uid];
    if (client.state !== 2) {
        return error(uid, "NO-AUTH-KICK");
    }

    if (cmd[param]) {
        console.log("RUNNING", uid, param);
        cmd[param].state = 1;
        emit('oncmdstate', uid, cmd[param]);
    }
}

function done(uid, param) {
    var socket = sockets[uid];
    var client = clients[uid];
    var cmd = cmds[uid];
    if (client.state !== 2) {
        return error(uid, "NO-AUTH-KICK");
    }
    if (cmd[param]) {
        console.log("COMPLETE", uid, param);
        cmd[param].state = 2;
        cmd[param].rtime = Date.now();
        emit('oncmdstate', uid, cmd[param]);
        // setTimeout(fetchResult, 100);
        if (FETCH_ON_EXEC) {
            process.nextTick(function () {
                fetch(uid, param);
            });
        }
    }
}

function result(uid, param) {
    var socket = sockets[uid];
    var cmd = cmds[uid];
    var client = clients[uid];
    if (client.state !== 2) {
        return error(uid, "NO-AUTH-KICK");
    }
    var id = param.indexOf(":");
    if (id < 0) return;
    id = param.substring(0, id);
    var stripped = param.substring(id.length + 1);
    console.log("ID FOUND", id);
    var spl = stripped.indexOf(":");
    if (spl < 0) {
        console.log("BAD FORMAT", id);
        return;
    }
    if (cmd[id] && cmd[id].state >= 1) {
        try {
            cmd[id].err = undefined;
            stripped = stripped.split(":");
            if (stripped.length < 4) {
                throw new Error("CORRUPT DATA");
            }
            var out = new Buffer(stripped[0], "base64");
            var err = new Buffer(stripped[1], "base64");
            var j = md5(out).trim().toLowerCase();
            var k = md5(err).trim().toLowerCase();
            var outm = stripped[2].trim().toLowerCase();
            var errm = stripped[3].trim().toLowerCase();

            if (!(j === outm && k === errm)) {
                cmd[id].rtime = Date.now();
                throw new Error("MD5 Checksum Failed");
            }
            out = out.toString("utf8").trim();
            err = err.toString("utf8").trim();
            console.log("RESULT", uid, id);
            // console.log(out, err);
            cmds_results[uid][id].out = out;
            cmds_results[uid][id].err = err;
            cmd[id].rtime = Date.now();
            cmd[id].state = 3;
            emit('oncmdstate', uid, cmd[id]);
            emit('oncmdresult', uid, [cmd[id] ,(cmds_results[uid][id].out.length + cmds_results[uid][id].err.length) > LAZYLOAD_SIZE ? 0 : cmds_results[uid][id]]);
        } catch (e) {
            console.log(e);
            console.log(e.stack);
            cmd[id].err = e;
            emit('oncmdresulterr', uid, cmd[id]);
            console.log("R_FAIL", param, uid, e);
        }
    }
}


function noresult(uid, param) {
    var socket = sockets[uid];
    var client = clients[uid];
    var cmd = cmds[uid];
    if (client.state !== 2) {
        return error(uid, "NO-AUTH-KICK");
    }
    if (cmd[param] && cmd[param].state >= 1) {
        console.log("NORESULT", param, uid);
        cmd[param].rtime = Date.now();
        emit('oncmdstate', uid, cmd[param]);
    }
}

function auth(uid, param) {
    var socket = sockets[uid];
    var client = clients[uid];
    console.log("AUTH", uid);
    
    if(CA_FailSafe || REPAIR_MODE) {
        console.log("AUTH_GOOD", uid);
        client.state = 2;
        emit('onauth', uid, client);
        clearTimeout(socket.denialClock);
        return;
    }
    if (client.state == 1) {
        try {
            var buf = new Buffer(param, "base64");
            for (var i = 0; i < PKList.length; i++) {
                try {
                    var dt = crypto.privateDecrypt(PKList[i], buf)
                    if (dt.toString('utf8').trim() === client.auth.challenge.toString("hex").toLowerCase()) {
                        console.log("AUTH_GOOD", uid);
                        client.state = 2;
                        emit('onauth', uid, client);
                        clearTimeout(socket.denialClock);
                        return;
                    } else {
                        console.log(dt);
                    }
                }
                catch (e) {
                    console.log(e);
                }
            }
        } catch (e) {
            return error(uid, "Wrong Auth Format " + param);
        }
        return error(uid, "Auth Failure (Key Fault)");
    } else {
        return error(uid, "State Error - Auth at ", client.state);
    }
}


function parse(uid, cmd) {
    var socket = sockets[uid];
    var client = clients[uid];
    // console.log(cmd);
    cmd = cmd.trim();
    if (!cmd.startsWith("{{") || cmd.indexOf("}}") < 0) {
        //other things
        // console.log(cmd);
        return;
    }

    var flag = cmd.substring(2, cmd.indexOf("}}")).toUpperCase();
    var data = cmd.substring(cmd.indexOf("}}") + 2).trim();
    // console.log(flag, uid, cmd);
    switch (flag) {
        case 'INIT':
            init(uid, data)
            break;
        case 'AUTH':
            auth(uid, data)
            break;
        case 'RUN':
            running(uid, data)
            break;
        case 'CMD':
            done(uid, data)
            break;
        case 'RESULT':
            result(uid, data)
            break;
        case 'NORESULT':
            noresult(uid, data)
            break;
    }
}

var server = tls.createServer(options, function (res) {

    if (!res.authorized) {
        console.log("REJECT", res.remoteAddress);
        return res.end();
    }

    var uid = uuid.v4();
    clients[uid] = {};
    cmds[uid] = {};
    cmds_results[uid] = {};
    cmd_sorts[uid] = [];
    sockets[uid] = res;
    var client = clients[uid];
    client.data = {};
    res.uid = client.uid = uid;
    client.state = 0;
    client.addr = res.remoteAddress;
    client.auth = {
        challenge: crypto.randomBytes(16).toString("hex")
    };

    res.denialClock = setTimeout(function () {
        error(res.uid, "AUTH TIMEOUT");
    }, DENYCLOCK);


    res.once("end", function () {
        console.log("END", uid, res.remoteAddress);
        cleanUp(uid);
    });
    res.once("error", function (e) {
        console.log("!ERR!", uid, e);
        res.end();
        cleanUp(uid);
    });

    var exploded = false;
    var buf = "";
    res.on('data', function (d) {
        if(exploded) return; //throw away
        d = d.toString();
        // console.log(d);
        //let's stream instead of split..
        for (var i = 0; i < d.length; i++) {
            if (d[i] == "\n") {
                if (buf.trim().length > 0) {
                    parse(uid, buf.trim());
                }
                buf = "";
            } else {
                buf += d[i];
                // console.log(buf);
                if (buf.length > SAFE_MEM) {
                    buf = undefined;
                    exploded = true;
                    return error(uid, "BUFFER OVERFLOW - FLOOD DETECTED");
                }
            }
        }
    });

    res.setKeepAlive(true, 10000);
    keepalive.setKeepAliveInterval(res, 3000)

    // and TCP_KEEPCNT
    keepalive.setKeepAliveProbes(res, 5)

    emit('onconnect', uid, client);
    console.log("CONNECT", uid, res.remoteAddress);
    
    // setTimeout(function(){
    //     sendCommand(uid, "cat /etc/config/wifidog");
    // }, 2000);
});


console.log("GATE START * CA:", CAList.length, " * PK:", PKList.length);
emit('hello');
server.listen(1444);



function babysitter() {
    var keys = Object.keys(clients);
    for (var i = 0; i < keys.length; i++) {
        var uid = keys[i];
        var sock = clients[uid];
        if (!sock) continue;

        var cks = Object.keys(cmds[uid]);
        var cmd = cmds[uid];
        var sort = cmd_sorts[uid];
        for (var j = 0; j < cks.length; j++) {
            // console.log(cks[j]);
            var id = cks[j];
            if (!cmd[id]) continue;
            var q;
            if (cmd[id].state == 3
                && ((Date.now() - cmd[id].rtime)) > CMD_CLEAN) {
                delete cmd[id];
                q = sort.indexOf(id);
                if (q >= 0) {
                    sort[q] = undefined;
                }
                delete cmds_results[uid][id];
                continue;
            }
            else if (((Date.now() - cmd[id].time)) > CMD_CLEAN * 10) {
                delete cmd[id];
                q = sort.indexOf(id);
                if (q >= 0) {
                    sort[q] = undefined;
                }
                delete cmds_results[uid][id];
                continue;
            }
            else if (cmd[id].state == 2
                && ((Date.now() - cmd[id].rtime)) > CMD_REFETCH) {
                fetch(uid, id);
            } 
            else if(cmd[id].state <= 1 && ((Date.now() - cmd[id].time)) > MAC_DEAD) {
                error(uid, "CMD DEADLOOP / STUCK - TERMINATING");
                break;
            }
        }
    }
}


setInterval(babysitter, BABYSIT_INTERVAL);


var api = express();
var http = require('http').Server(api);
var io = require('socket.io')(http);
var bodyParser = require('body-parser');
var serveStatic = require('serve-static');
 

// parse application/x-www-form-urlencoded 
//api.use(bodyParser.urlencoded({ extended: false }))
 
// parse application/json 
api.use(bodyParser.json())

var numUsers = 0;

io.on('connection', function (socket) {
    var addedUser = false;
    io.emit("commander", {});
    socket.on('disconnect', function () {
        if (addedUser) {
            --numUsers;
            // echo globally that this client has left
            socket.broadcast.emit('user left', {
                numUsers: numUsers
            });
        }
    });
});

// [ aijie uid (db) ]    [ uid ] <-> networkid 
var clk;
function serverreload(time) {
    console.log("Gate Reloading in T-" + time);
    clearTimeout(clk);
    clk = setTimeout(function(){
        console.log("* Gate Closing *");
        process.exit();
    }, time * 1000) ;
}

function cancelreload() {
    console.log("Cancel Gate Reload");
    clearTimeout(clk);
}

// server reload?

// api.get("/", function (req, res) {
//     res.sendFile(__dirname + "/dash/index.html");
// });

api.get("/server_reload", function (req, res) {
    res.status(200).json({
        result: "Server Reloading in 10 secs"
    });
    serverreload(10);
});


api.get("/cafailsafe", function (req, res) {
    res.status(200).json({
        result: "CA FailSafe Activated (window - 60 seconds)"
    });
    CA_FailSafe = true;
    setTimeout(function(){
        CA_FailSafe = false;
    }, 60000);
});


api.get("/dcafailsafe", function (req, res) {
    res.status(200).json({
        result: "Exiting CA FailSafe"
    });
    CA_FailSafe = false;
});

api.get("/repairmode", function (req, res) {
    res.status(200).json({
        result: "REPAIR WINDOW 60 SEC"
    });
    REPAIR_MODE = true;
    setTimeout(function(){
        REPAIR_MODE = false;
    }, 60000);
});


api.get("/drepairmode", function (req, res) {
    res.status(200).json({
        result: "EXIT REPAIR WINDOW"
    });
    REPAIR_MODE = false;
});

api.get("/server_reload/:time", function (req, res) {
    var time = parseInt(req.params["time"]);
    res.status(200).json({
        result: "Server Reloading in " + time + " secs"
    });
    serverreload(time);
});

api.get("/cancel_reload", function (req, res) {
    res.status(200).json({
        result: "Reload Canceled"
    });
    cancelreload();
});

// list clients
api.get("/clients", function (req, res) {
    res.status(200).json(clients);
});

// get client detail
api.get("/clients/:id", function (req, res) {
    var id = req.params['id'];
    res.status(200).json( {
        id: id,
        client: clients[id],
        cmds: cmds[id] }
    );
});

// byebye
api.delete("/clients/:id", function (req, res) {
    var id = req.params['id'];
    sockets[id].end();
    res.status(200).json({
        id: id,
        result: 'done'
    });
});

// list cmds
api.get("/:id/cmds", function (req, res) {
    var id = req.params['id'];
    res.status(200).json(cmds[id]);
});

// gather result
api.get("/:id/cmds/:cmdid", function (req, res) {
    var id = req.params['id'];
    var cmdid = req.params['cmdid'];
    res.status(200).json({
       cmd: cmds[id][cmdid],
       result: cmds_results[id][cmdid]
    });
});

// send cmd
api.post("/:id/cmd", function (req, res) {
    console.log(req.body);
    var c = req.body.cmd;
    var id = req.param("id");
    var cid = sendCommand(id, c);
    res.status(200).json({
        id: cid
    });
});

api.use(express.static('dash'));
// close connection

// get result
http.listen(2560, function () {
    console.log('listening on *:2560');
});




























const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});



rl.on('line', (cmd) => {
    if (cmd.trim().length > 0) {

        var keys = Object.keys(clients);
        for (var i = 0; i < keys.length; i++) {
            var uid = keys[i];
            var sock = sockets[uid];
            if (!sock) continue;

            if (cmd == "STOPALL") {
                sock.end();
                continue;
            }

            if (cmd == "MULTILINE") {
                sendCommand(uid, `
echo hello
echo hello2
echo hello3
            `)
                continue;
            }

            sendCommand(uid, cmd);

        }
    }
});

