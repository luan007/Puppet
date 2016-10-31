const net = require("net");
const cluster = require("cluster");
const tls = require("tls");
const fs = require("fs");

//process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";


//socat ssl-l:1443,reuseaddr,fork,cert=server.pem,cafile=client.crt,verify=1 exec:'uptime'
//socat - ssl:localhost:1443,cert=client.pem,cafile=server.crt,verify=0
if (cluster.isMaster) {
    function job() {
        var worker = cluster.fork();
        worker.on("exit", function () {
            console.log("NODE EXIT - FORK");
            job();
        });
    }
    job();
}
else {
    require('./singleton.js'); //jump in..
    var api = require("./api/server.js").build("aijee", false);
    api.listen(2561);
}
// var i = 0;
// var server = net.createServer(function(con) {
//     i++;
//     var t = i;
//     var j = setInterval(function(){
//         //con.write("ifconfig | grep eth\n");
//     }, 5000);
    
//     console.log("+ #" + t);
    
//     con.on("data", function(d){
//         //console.log(d.toString());
        
//         //middleware infrastructure
        
//         // con.write("export PS1=''\n");
//         // con.write("stty -echo\n");
        
//     });
//     con.on("end", function(){
//         clearInterval(j);
//         console.log("x #" + t);
//     });
    
// });

// //tcp:127.0.0.1:2024


//socat exec:"sh /tmp/hehe.sh",pty,setsid,setpgid,stderr,ctty ssl:localhost:1443,cert=client.pem,cafile=server.crt,verify=0


// console.log("server listen @ 2024")
// server.listen(2024)