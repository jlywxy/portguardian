/*
    Portguardian API
    Version 1.01
*/
const http = require('http')
const net = require('net')
const fs = require('fs')
const crypto = require('crypto');
const eccrypto = require('eccrypto')
const exec = require('child_process').execSync
const apiVersion = "1.01"

//--------------------------------

var tokenExpiration = 1000 * 60 * 60 * 12
var windowTimeout = 1000 * 30
var guardPort = 20003
var servicePort = 20002
var pgdb = "./pgdb.json"
var connLimitController = {
    map: {},
    throttlingCount: 5,
    checkInterval: 3
}

//comment following code when deploy to production env.

// net.createServer((socket)=>{
//     setInterval(()=>{
//         socket.write("data from "+guardPort)
//     },1000)
// }).listen(guardPort)

//--------------------------------

var pgdbObj = {}
var windowtimer = {}
var windowtimer_override = {}
var portOverrided = false
var connstate = true
var conndetail=""
var connstatetimer = setInterval(() => {
    try {
        conndetail=exec("netstat -an|grep " + guardPort).toString()
        connstate = true
    } catch (e) {
        conndetail=e.toString()
        connstate = false
    }
}, 5000)
var iptables = {
    clearIP: (ip = null) => {
        try {
            for (let prevRule of exec("iptables -S|grep " + guardPort + (ip ? ("|grep " + ip) : "")).toString().split("\n")) {
                if (prevRule != '') {
                    console.log("iptables: clearing previous rule: " + prevRule)
                    console.log("exec: iptables -D " + prevRule.substring(3))
                    exec("iptables -D " + prevRule.substring(3))
                }

            }
        } catch (e) {
            console.log("iptables: no previous rules " + ip ? ("for " + ip) : "")
        }
    },
    clearAll: () => {
        iptables.clearIP()
    },
    dropAll: () => {
        exec("iptables -I INPUT -p tcp --dport " + guardPort + " -j DROP")
    },
    allowIP: (ip) => {
        iptables.clearIP(ip)
        exec("iptables -I INPUT -s " + ip + " -p tcp --dport " + guardPort + " -j ACCEPT")
    },
    dropIPNew: (ip) => {
        exec("iptables -I INPUT -s " + ip + " -p tcp --dport " + guardPort + " -m state --state NEW -j DROP")
    },
    allowOverride: () => {
        exec("iptables -I INPUT -p tcp --dport " + guardPort + " -j ACCEPT")
    },
    clearOverride: () => {
        exec("iptables -D INPUT -p tcp --dport " + guardPort + " -j ACCEPT")
        exec("iptables -I INPUT -p tcp --dport " + guardPort + " -m state --state NEW -j DROP")
    }
}


setInterval(() => {
    connLimitController.map = {}
}, connLimitController.checkInterval * 1000)

var server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', "*");
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE, OPTIONS');

    req.on('data', (chunk) => {
        let ip = getRemoteIP(req).replace("::ffff:", "")
        if (typeof connLimitController.map[ip] == 'undefined') {
            connLimitController.map[ip] = 0
        } else {
            connLimitController.map[ip] += 1
            if (connLimitController.map[ip] > connLimitController.throttlingCount) {
                console.log("reject request from " + ip + ", " + chunk.toString())
                responser.errorEmitter.connectThrottling(res)
                return
            }
        }
        console.log("new request from " + ip + ", " + chunk.toString())
        try {
            let obj = JSON.parse(chunk.toString())
            if (!obj.type) {
                responser.errorEmitter.invalidJSONSyntax(res, 1)
                return
            }
            try {
                let token = obj.token
                let account = obj.account
                switch (obj.type) {
                    case "login":
                        {
                            let passwordHash = obj.body.code
                            if (typeof pgdbObj.users[account] == 'undefined') {
                                responser.errorEmitter.noSuchUser(res)
                                return
                            } else {
                                if (pgdbObj.users[account].passwordHash != passwordHash) {
                                    responser.errorEmitter.noSuchUser(res, 1)
                                    return
                                } else {
                                    let sessionPrivKey = eccrypto.generatePrivate()
                                    let sessionPubKey = eccrypto.getPublic(sessionPrivKey)

                                    pgdbObj.users[account].priv = sessionPrivKey.toString('hex')
                                    pgdbObj.users[account].pub = sessionPubKey.toString('hex')
                                    dbOp.save()
                                    eccrypto.encrypt(sessionPubKey, JSON.stringify({
                                        time: Date.now(),
                                        availableUntil: Date.now() + tokenExpiration,
                                        account: account
                                    })).then((encrypted) => {
                                        let token = encSerialize(encrypted)
                                        responser.reponseJSON(res, {
                                            token: token
                                        })
                                        validateToken(token, account)
                                        dbOp.save()
                                    })
                                }
                            }
                        }
                        break
                    case "portauth":
                        {
                            validTokenAndAction(token, account, ip, res, () => {
                                if (portOverrided) {
                                    responser.errorEmitter.custom(res, "管理员已全局开启端口", 0)
                                    return
                                }
                                pgdbObj.users[account].authTime = Date.now()
                                dbOp.save()
                                iptables.allowIP(ip)
                                clearInterval(windowtimer[account])
                                windowtimer[account] = setTimeout(() => {
                                    iptables.dropIPNew(ip)
                                    console.log("closed new connection for " + ip)
                                    pgdbObj.users[account].portstate = {
                                        state: "auth_limited",
                                        optime: new Date().toString()
                                    }
                                    dbOp.save()
                                }, windowTimeout)
                                pgdbObj.users[account].portstate = {
                                    state: "auth_opened",
                                    optime: new Date().toString()
                                }
                                dbOp.save()
                                responser.reponseJSON(res, { result: "ok" })
                            })
                            // validateToken(token, account, (valRes, valCode) => {
                            //     if (!valRes) {
                            //         iptables.clearIP(ip)
                            //         responser.errorEmitter.invalidToken(res, valCode)
                            //         return
                            //     } else {
                            //         pgdbObj.users[account].authTime = Date.now()
                            //         dbOp.save()
                            //         iptables.allowIP(ip)
                            //         setTimeout(() => {
                            //             iptables.dropIPNew(ip)
                            //             console.log("closed new connection for " + ip)
                            //         }, windowTimeout)
                            //         responser.reponseJSON(res, { result: "ok" })
                            //     }
                            // })
                        }
                        break
                    case "portoverride":
                        validTokenAndAction(token, account, ip, res, () => {
                            if (validAdmin(res, account)) {
                                clearInterval(windowtimer_override)
                                iptables.allowOverride()
                                for (let u of Object.keys(pgdbObj.users)) {
                                    pgdbObj.users[u].portstate = {
                                        state: "auth_global",
                                        optime: new Date().toString()
                                    }
                                }
                                dbOp.save()
                                portOverrided = true
                                windowtimer_override = setTimeout(() => {
                                    for (let u of Object.keys(pgdbObj.users)) {
                                        pgdbObj.users[u].portstate = {
                                            state: "auth_global_limited",
                                            optime: new Date().toString()
                                        }
                                    }
                                    dbOp.save()
                                    iptables.clearOverride()
                                    portOverrided = false
                                },windowTimeout)
                                responser.reponseJSON(res, { result: "ok" })
                            }
                        })
                        break
                    case "modpass":
                        {
                            let passwordHash = obj.body.code
                            let passwordHashNew = obj.body.codenew
                            if (!passwordHashNew) {
                                responser.errorEmitter.invalidJSONSyntax(res, 3)
                                return
                            }
                            validTokenAndAction(token, account, ip, res, () => {
                                try {
                                    if (pgdbObj.users[account].passwordHash != passwordHash) {
                                        responser.errorEmitter.noSuchUser(res, 2)
                                        return
                                    } else {
                                        pgdbObj.users[account].passwordHash = passwordHashNew
                                        dbOp.save()
                                    }
                                } catch (e) {
                                    responser.errorEmitter.anonymousError(res, e)
                                    return
                                }
                                responser.reponseJSON(res, { result: "ok" })
                            })
                        }
                        break
                    case "portunauth":
                        {
                            validTokenAndAction(token, account, ip, res, () => {
                                clearInterval(windowtimer[account])
                                iptables.clearIP(ip)
                                pgdbObj.users[account].portstate = {
                                    state: "unauth",
                                    optime: new Date().toString()
                                }
                                dbOp.save()
                                responser.reponseJSON(res, { result: "ok" })
                            })
                        }
                        break
                    case "userstat":
                        {
                            validTokenAndAction(token, account, ip, res, () => {
                                responser.reponseJSON(res, {
                                    portstate: pgdbObj.users[account].portstate,
                                    connstate: connstate,
                                    conndetail: conndetail,
                                    time: Date.now(),
                                    isadmin: pgdbObj.admins.indexOf(account)!=-1 ? true : false
                                })
                            })
                        }
                        break
                    case "infolist":
                        {
                            validTokenAndAction(token, account, ip, res, () => {
                                if (validAdmin(res, account)) {
                                    responser.reponseJSON(pgdbObj)
                                }
                            })
                        }
                        break
                    case "adduser":
                        {
                            validTokenAndAction(token, account, ip, res, () => {
                                if (validAdmin(res, account)) {
                                    let accountNew = obj.body.account
                                    let passwordHashNew = obj.body.code
                                    if (!accountNew || !passwordHashNew || accountNew == "" || passwordHashNew == "") {
                                        responser.errorEmitter.invalidJSONSyntax(res, 3)
                                        return
                                    }
                                    pgdbObj.users[accountNew] = { passwordHash: '' }
                                    pgdbObj.users[accountNew].passwordHash = passwordHashNew
                                    dbOp.save()

                                    console.log(" * addeded user " + accountNew + "by" + account)

                                    responser.reponseJSON(res, { result: "ok" })
                                }
                            })
                        }
                        break
                    case "deluser":
                        {
                            validTokenAndAction(token, account, ip, res, () => {
                                if (validAdmin(res, account)) {
                                    let accountExist = obj.body.account
                                    if (!accountExist || accountExist == "") {
                                        responser.errorEmitter.invalidJSONSyntax(res, 3)
                                        return
                                    }
                                    if (pgdbObj.admins.indexOf(accountExist)!=-1) {
                                        responser.errorEmitter.permissionDenied(res, 1)
                                        return
                                    }
                                    pgdbObj.users[accountExist] = {}
                                    delete pgdbObj.users[accountExist]
                                    dbOp.save()

                                    console.log(" * deleted user " + accountExist + "by" + account)
                                    responser.reponseJSON(res, { result: "ok" })
                                }
                            })
                        }
                        break
                    default:
                        responser.errorEmitter.invalidJSONSyntax(res, 2)
                }
            } catch (e) {
                responser.errorEmitter.anonymousError(res, e)
                return
            }
        } catch (e) {
            console.log(e)
            responser.errorEmitter.invalidJSONSyntax(res)
            return
        }
    })
})
function encSerialize(encrypted) {
    return Buffer.from(JSON.stringify({
        iv: encrypted.iv.toString('hex'),
        mac: encrypted.mac.toString('hex'),
        ephemPublicKey: encrypted.ephemPublicKey.toString('hex'),
        ciphertext: encrypted.ciphertext.toString('hex'),
    })).toString('hex')
}
function encDeserialize(encryptedhex) {
    let raw = JSON.parse(Buffer.from(encryptedhex, 'hex').toString())
    return {
        iv: Buffer.from(raw.iv, 'hex'),
        mac: Buffer.from(raw.mac, 'hex'),
        ephemPublicKey: Buffer.from(raw.ephemPublicKey, 'hex'),
        ciphertext: Buffer.from(raw.ciphertext, 'hex')
    }
}
function validAdmin(res, account) {
    if (pgdbObj.admins.indexOf(account) != -1) {
        return true
    } else {
        responser.errorEmitter.permissionDenied(res)
        return false
    }
}
function validTokenAndAction(token, account, ip, res, callBack) {
    validateToken(token, account, (valRes, valCode) => {
        if (!valRes) {
            iptables.clearIP(ip)
            responser.errorEmitter.invalidToken(res, valCode)
            return
        } else {
            callBack()
        }
    })
}
function validateToken(token, account, callBack = () => { }) {
    try {
        let privKey = Buffer.from(pgdbObj.users[account].priv, 'hex')
        eccrypto.decrypt(privKey, encDeserialize(token)).then((t) => {
            let tk = JSON.parse(t.toString())
            if (tk.availableUntil < Date.now()) {
                console.log("token expired")
                callBack(false, 1)
            } else {
                callBack(true)
            }
        }).catch((e) => {
            console.log("token valid false(2): " + e)
            callBack(false, 2)
        })
    } catch (e) {
        console.log("token valid false(0): " + e)
        callBack(false, 0)
    }
}
function getRemoteIP(req) {
    //https://blog.csdn.net/weixin_30539625/article/details/95080664
    return req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress
}
var responser = {
    errorEmitter: {
        invalidJSONSyntax: (res, code = 0) => { //code —— 3: 业务所需字段未提供，2: 业务类型未能匹配（协议不支持），1: 未提供业务类型，0: 非标准JSON格式
            responser.reponseJSON(res, {
                error: "Invalid request body syntax",
                type: 0,
                code: code
            })
        },
        noSuchUser: (res, code = 0) => { //code —— 0: 无此用户，1: 密码不正确，2: 修改密码时旧密码错误
            responser.reponseJSON(res, {
                error: "User and/or password mismatch",
                type: 1,
                code: code
            })
        },
        connectThrottling: (res, code = 0) => {
            setTimeout(() => {
                responser.reponseJSON(res, {
                    error: "Connection throttling",
                    type: 2,
                    code: code
                })
            }, 5000)
        },
        anonymousError: (res, e) => {
            responser.reponseJSON(res, {
                error: e.toString(),
                type: 3,
                code: -1
            })
        },
        invalidToken: (res, code = 0) => {
            responser.reponseJSON(res, {
                error: "Invalid token",
                type: 4,
                code: code
            })
        },
        permissionDenied: (res, code = 0) => {// code —— 0: 非管理员用户试图使用管理员功能，1: 管理员用户试图更改其他管理员信息
            responser.reponseJSON(res, {
                error: "Permission denied",
                type: 5,
                code: code
            })
        },
        custom: (res, text, code = 0) => {
            responser.reponseJSON(res, {
                error: text,
                type: -1,
                code: code
            })
        }
    },
    reponseJSON(res, jsonObj) {
        jsonObj.version = apiVersion
        try{
            res.write(JSON.stringify(jsonObj))
            res.end()
        }catch(e){
            console.log("cancelled writing to "+ip)
        }
    }
}

var dbOp = {
    save: () => {
        try {
            fs.writeFileSync(pgdb, JSON.stringify(pgdbObj))
        } catch (e) {

        }
    },
    load: () => {
        try {
            pgdbObj = JSON.parse(fs.readFileSync(pgdb).toString())
        } catch (e) {
            console.log("error loading database")
            process.exit(0)
        }
    }
}

console.log("\n * PortGuardian " + apiVersion + " * \n")
dbOp.load()
console.log("Loaded DB")
server.listen(servicePort)
console.log("Listening on port " + servicePort)

iptables.clearAll()
iptables.dropAll()