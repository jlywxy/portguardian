var mono = new Mono(document)

var pgVersion = {
    ui: "1.2",
    mono: monoversion.mono
}

var apiurl
var guardurl
var guardname
switch (page.params) {
    case "mvt":
        guardname = "mc.vlist.tk"
        apiurl = "https://jlywxy.top/portguardian-api/vlistmc"
        guardurl = "mc.vlist.tk"
        break;
    default:
        guardname = "teleportmc"
        apiurl = "https://jlywxy.top/portguardian-api/teleportmc"
        guardurl = "teleport.jlywxy.top:20003"
}
var authtimeoutDefault = 30

function errorReceived(obj, filter = []) {
    if (obj.error) {
        if (filter.indexOf(obj.type) != -1) return false
        console.log(obj)
        switch (obj.type) {
            case -1:
                MonoDialog.new(mono, obj.error)
                break;
            case 0:
                switch (obj.code) {
                    case 0: case 1:
                        MonoDialog.new(mono, "不受支持的协议", "请使用最新版本客户端。")
                        break;
                    case 2: case 3:
                        MonoDialog.new(mono, "不受支持的协议", "联系管理员更新软件版本。")
                        break;
                }
                break;
            case 1:
                switch (obj.code) {
                    case 0:
                        MonoDialog.new(mono, "用户名或密码错误", "用户不存在")
                        break
                    case 1:
                        MonoDialog.new(mono, "用户名或密码错误", "密码错误")
                        break
                    case 2:
                        MonoDialog.new(mono, "操作失败", "旧密码错误")
                        break
                }
                break;
            case 2:
                MonoDialog.new(mono, "服务器拒绝当前请求", "请稍后再试")
                break;
            case 3:
                MonoDialog.new(mono, "未知错误", obj.error)
                break;
            case 4:
                MonoDialog.new(mono, "操作失败", "用户鉴权失败，请重新登录。")
                break;
            case 5:
                switch (obj.code) {
                    case 0:
                        MonoDialog.new(mono, "操作被拒绝", "目前登录的用户没有进行此操作的权限。")
                        break
                    case 1:
                        MonoDialog.new(mono, "操作被拒绝", "系统已拒绝此用户的操作：管理员权限冲突。")
                }
                break;
            default:
                MonoDialog.new(mono, "未知错误: 不受支持的协议", "Error Type " + obj.type + "/" + obj.code + ":" + obj.error)
        }
        return true
    }
    return false
}
function removeToken() {
    localStorage.removeItem(pageParams + "_account")
    localStorage.removeItem(pageParams + "_token")
}
var portguardianAPI = {
    login: (account, code, callBack) => {
        monoAjax.postJson({
            type: "login",
            account: account,
            body: {
                "code": sha256(code)
            }
        }, apiurl, (r) => {
            let res = r.responseText
            let obj = JSON.parse(res)
            if (errorReceived(obj, [1])) return
            if (obj.token) {
                localStorage.setItem(pageParams + "_token", obj.token)
                localStorage.setItem(pageParams + "_account", account)
                console.log("logged in as " + account)
                controls.userident.text = "用户: " + localStorage.getItem(pageParams + "_account")
                callBack(true)
            } else {
                console.log("login failed: " + res)
                callBack(false)
            }
        }, (err) => {
            callBack(false, err)
        })
    },
    logout: () => {
        logui.login()
        portguardianAPI.portunauth(() => {
            removeToken()
        })

    },
    portunauth: (callBack) => {
        shownetIndicator()
        monoAjax.postJson({ "type": "portunauth", account: localStorage.getItem(pageParams + "_account"), token: localStorage.getItem(pageParams + "_token") }, apiurl, (r) => {
            hidenetIndicator()
            callBack()
        })
    },
    modpass: () => {

        if (controls.modpass_newpass.text != controls.modpass_newpass2.text) {
            MonoDialog.new(mono, "新密码输入不一致")
            controls.modpass_oldpass.text = ""
            controls.modpass_newpass.text = ""
            controls.modpass_newpass2.text = ""
            return
        }
        if (controls.modpass_newpass.text == "" || controls.modpass_newpass2.text == "") {
            MonoDialog.new(mono, "新密码为空")
            controls.modpass_oldpass.text = ""
            controls.modpass_newpass.text = ""
            controls.modpass_newpass2.text = ""
            return
        }
        shownetIndicator()
        monoAjax.postJson({
            type: "modpass",
            account: localStorage.getItem(pageParams + "_account"), token: localStorage.getItem(pageParams + "_token"),
            body: {
                code: sha256(controls.modpass_oldpass.text),
                codenew: sha256(controls.modpass_newpass.text)
            }
        }, apiurl, (r) => {
            hidenetIndicator()
            let obj = JSON.parse(r.responseText)
            if (obj.error) {
                if (errorReceived(obj)) {
                    controls.modpass_oldpass.text = ""
                    controls.modpass_newpass.text = ""
                    controls.modpass_newpass2.text = ""
                    return
                }
                return
            } else {
                MonoDialog.new(mono, "密码修改成功")
                controls.modpass_oldpass.text = ""
                controls.modpass_newpass.text = ""
                controls.modpass_newpass2.text = ""
            }
        })
    },
    adduser: (account, code) => {
        shownetIndicator()
        monoAjax.postJson({ "type": "adduser", account: localStorage.getItem(pageParams + "_account"), token: localStorage.getItem(pageParams + "_token"), body: { account: account, code: sha256(code) } }, apiurl, (r) => {
            hidenetIndicator()
            let obj = JSON.parse(r.responseText)
            if (errorReceived(obj)) {
                return
            } else {
                MonoDialog.new(mono, "已新建用户")
                controls.newaccount.text = ""
                controls.newpass.text = ""
            }
        })
    },
    deluser: (account) => {
        shownetIndicator()
        monoAjax.postJson({ "type": "deluser", account: localStorage.getItem(page.params + "_account"), token: localStorage.getItem(page.params + "_token"), body: { account: account } }, apiurl, (r) => {
            hidenetIndicator()
            let obj = JSON.parse(r.responseText)
            if (errorReceived(obj)) {
                return
            } else {
                MonoDialog.new(mono, "已删除用户")
                controls.newaccount.text = ""
                controls.newpass.text = ""
            }
        })
    },
    overridePort: () => {
        shownetIndicator()
        monoAjax.postJson({ "type": "portoverride", account: localStorage.getItem(pageParams + "_account"), token: localStorage.getItem(pageParams + "_token") }, apiurl, (r) => {
            hidenetIndicator()
            let obj = JSON.parse(r.responseText)
            if (errorReceived(obj)) {
                return
            } else {
                MonoDialog.new(mono, "已全局开启端口，30秒后自动关闭。")
            }
        })
    },
    openPort: () => {
        shownetIndicator()
        monoAjax.postJson({ "type": "portauth", account: localStorage.getItem(pageParams + "_account"), token: localStorage.getItem(pageParams + "_token") }, apiurl, (r) => {
            hidenetIndicator()
            let obj = JSON.parse(r.responseText)
            if (errorReceived(obj)) {
                return
            } else {
                controls.statetext.text = "✅已开启端口，请在30秒内连接 <b>" + guardurl + "</b>"
                portguardianAPI.getState()
                let authtimer
                authtimeout = authtimeoutDefault
                clearInterval(authtimer)
                authtimer = setInterval(() => {
                    authtimeout--
                    if (authtimeout <= 0) {
                        clearInterval(authtimer)
                        controls.statetext.text = "端口新连接请求许可已关闭，已经连接的不受影响。<br>⬆️如需重新连接需开启端口。"
                        controls.statetext.properties.style.color = "black"
                        controls.statetext.update()
                        return
                    }
                    controls.statetext.text = "✅已开启端口，请在" + authtimeout + "秒内连接 <b>" + guardurl + "</b>"
                }, 1000)
                controls.statetext.properties.style.color = "green"
                controls.statetext.update()
            }
        })
    },
    getState: () => {
        monoAjax.postJson({ "type": "userstat", account: localStorage.getItem(pageParams + "_account"), token: localStorage.getItem(pageParams + "_token") }, apiurl, (r) => {
            let obj = JSON.parse(r.responseText)
            console.log(obj)
            if (obj.error) {
                controls.port.realstate.text = "-"
                controls.lastoptime.text = "-"
                controls.pgapiversion.text = "-"
                if (obj.type == 4) {
                    controls.port.openstate.text = "⚠️需要重新登录"
                    if (logui.loggedin) { logui.loggedin = false; MonoDialog.new(mono, "登录信息已过期", "请重新登录", [{ text: "OK", onclick: logui.login }]) }
                    removeToken()
                    return
                } else {
                    controls.port.openstate.text = "⚠️不受支持的协议"
                    return
                }
            } else {
                if (!obj.portstate) {
                    controls.port.openstate.text = "未初始化"
                }
                if (obj.isadmin) {
                    panels.admin.properties.style.display = "block"
                    panels.admin.update()
                }
                controls.lastoptime.text = "🕙上次操作时间: " + obj.portstate.optime.replace("GMT+0800 (中国标准时间)", "")
                controls.pgapiversion.text = "PortGuardian API 版本 " + (obj.version ? obj.version : "0.9")
                switch (obj.portstate.state) {
                    case "auth_limited":
                        controls.port.openstate.text = "✅端口已开放(限制性)"
                        break;
                    case "auth_opened":
                        controls.port.openstate.text = "✅端口已开放"
                        break;
                    case "auth_global":
                        controls.port.openstate.text = "✅端口已开放(管理员超控)"
                        break;
                    case "auth_global_limited":
                        controls.port.openstate.text = "✅端口已开放(限制性,管理员超控)"
                        break;
                    case "unauth":
                        controls.port.openstate.text = "端口未开放"
                        break;
                    default:
                        controls.port.openstate.text = "⚠️不受支持的协议: 端口开放状态" + obj.portstate.state
                }
                switch (obj.connstate) {
                    case false:
                        controls.port.realstate.text = "⚠️端口无法连通，请联系管理员"
                        break;
                    default:
                        controls.port.realstate.text = "✅端口可连通"
                }
            }
        }, () => {
            controls.port.openstate.text = "⚠️网络错误"
        })
    }
}






var logui = {
    login: () => {
        controlpanel.properties.style.display = "none"
        controlpanel.update()
        loginpanel.properties.style.display = "block"
        loginpanel.update()
        logui.loggedin = false
        clearInterval(stateTimer)
    },
    logout: () => {
        loginpanel.properties.style.display = "none"
        loginpanel.update()
        controlpanel.properties.style.display = "block"
        controlpanel.update()
        logui.loggedin = true
        stateTimer = setInterval(portguardianAPI.getState, 3000)
    },
    loggedin: false
}
function shownetIndicator() {
    controls.netindicator.properties.style.display = "block"
    controls.netindicator.update()
}
function hidenetIndicator() {
    controls.netindicator.properties.style.display = "none"
    controls.netindicator.update()
}
var controls = {
    netindicator: new TinyView({
        innerHTML: ios_indicator_svg,
        style: {
            margin: "0 auto",
            height: "20px",
            width: "20px",
            display: "none"
        }
    }),
    userident: new Text("用户: jlywxy"),
    port: {
        openstate: new ListTextItem("正在获取端口状态"),
        realstate: new ListTextItem("-")
    },
    lastoptime: new ListTextItem("-"),
    statetext: new TextHint("⬆️开启端口授权连接"),
    pgapiversion: new TextHint("-"),

    modpass_oldpass: new Textbox(null, "旧密码", null, true),
    modpass_newpass: new Textbox(null, "新密码", null, true),
    modpass_newpass2: new Textbox(null, "再次输入新密码", null, true),

    login_account: new Textbox(null, "账号"),
    login_pass: new Textbox(null, "密码", null, true),

    newaccount: new Textbox(null, "用户名"),
    newpass: new Textbox(null, "密码", null, true),
}
var panels = {
    user: new View([
        new View([
            new View([controls.userident,], {
                style: {
                    position: "absolute",
                    left: "20px",
                    top: "3px",
                }
            }),
            new View([
                new MonoInlineButton("退出登录", () => {
                    MonoDialog.new(mono, "退出登录后是否要关闭端口？", "选择关闭端口会断开现有连接，选择仅退出则会保留现有连接。", [
                        {
                            text: "是",
                            onclick: portguardianAPI.logout
                        },
                        {
                            text: "否",
                            onclick: () => { logui.login(); removeToken() }
                        },
                        { text: "取消" }
                    ])
                })
            ], {
                style: {
                    display: "inline-block",
                    width: "120px",
                    position: "absolute",
                    top: "-1px",
                    right: "0px"
                }
            })
        ], {
            style: {
                "background-color": "#efefef",
                "border-radius": "40px",
                "width": "270px",
                "height": "40px",
                "text-align": "left",
                "margin": "0 auto",
                "position": "relative "
            }
        })

    ]),
    admin: new View([
        new VSpacer(10),
        new ListHint("管理员控制台"),
        new List([
            new ListButton("端口超控", () => {
                portguardianAPI.overridePort()
            }),
        ]),
        new List([
            new ListItem([controls.newaccount]),
            new ListItem([controls.newpass]),
            new ListButton("新建用户", () => {
                portguardianAPI.adduser(controls.newaccount.text, controls.newpass.text)

            }),
            new ListButton("删除用户", () => {
                portguardianAPI.deluser(controls.newaccount.text)

            })
        ]),
    ], {
        style: {
            display: "none"
        }
    })
}

let loginState = 0
var loginpanel = new View([
    new View([
        new VerticalPadding(30),
        new TinyView({ innerHTML: "登录授权", style: { "text-align": "center", "font-size": "18px" } }),
        new VerticalPadding(20),
        accountText = new TextField(controls.login_account),
        new VerticalPadding(10),
        codeText = new TextField(controls.login_pass),
        new VerticalPadding(30),
        clickButton = new TinyView({
            innerHTML: "登录",
            style: {
                "-webkit-appearance": "none",
                "border": "none",
                "border-radius": "8px",
                "padding": "9px",
                "font-size": "15px",
                "background-color": "#00a0f0",
                "color": "white",
                "outline": "none",
                "text-align": "center"
            },
            attributes: {
                onclick: () => {
                    if (loginState != 1) {
                        loginState == 1
                        clickButton.text = "<div style='width:18px;height:18px;margin:0 auto;filter:invert(100%);-webkit-filter:invert(100%)'>" + ios_indicator_svg + "</div>"
                        clickButton.properties.style["background-color"] = "#808080"
                        clickButton.update()

                        portguardianAPI.login(controls.login_account.text, controls.login_pass.text, (state, err) => {
                            if (state) {
                                logui.logout()
                                portguardianAPI.getState()
                                controls.login_pass.text = ""
                            } else {
                                if (err) {
                                    MonoDialog.new(mono, "登录失败", "网络错误")
                                } else {
                                    MonoDialog.new(mono, "登录失败", "用户名或密码错误")
                                }
                            }
                            clickButton.properties.innerHTML = "登录"
                            clickButton.properties.style["background-color"] = "#00a0f0"
                            clickButton.update()
                        })
                    }
                }
            }
        })
    ], {
        style: {
            width: "280px",
            height: "250px",
            left: "50%",
            top: "50%",
            transform: "translate(-50%,-50%)",
            position: "absolute",
            "border-radius": "20px",
            "background-color": "#e9e9e9",
            "padding-left": "28px",
            "padding-right": "28px",
        }
    })
])
var controlpanel = new View([
    new VSpacer(65),
    new View([
        new VSpacer(60),
        new ListHint("状态"),
        new List([
            controls.port.openstate,
            controls.port.realstate,
            controls.lastoptime,

        ]),

        new VSpacer(20),
        new ListHint("修改密码"),
        new List([
            new ListItem([controls.modpass_oldpass]),
            new ListItem([controls.modpass_newpass]),
            new ListItem([controls.modpass_newpass2]),
            new ListButton("修改密码", () => {
                portguardianAPI.modpass()
            })
        ]),
        panels.admin
    ], {
        style: {
            width: "240px",
            "background-color": "#F0F0F0",
            top: 0,
            bottom: 0,
            position: "absolute",
            "z-index": 2,
            "overflow": "scroll"
        }
    }),
    new View([
        new View([
            controls.netindicator,
            new VSpacer(15),
            panels.user,
            new VSpacer(35),
            new MonoInlineButton("开启端口", () => {
                portguardianAPI.openPort()
            }),

            new VSpacer(15),
            controls.statetext,

            new MonoInlineButton("关闭端口", () => {
                portguardianAPI.portunauth()
            }),
            new VSpacer(15),
            new TextHint("🤒️请勿开启vpn或代理时连接服务器（或将本网站设置为代理白名单），无法连接时请尝试更换网络（使用宽带而非移动热点共享）或联系管理员。"),
            new VSpacer(100),
            new TextHint("PortGuardian Mono.js UI 版本 " + pgVersion.ui),
            controls.pgapiversion,
            new TextHint("Mono.js 版本 " + pgVersion.mono),
        ], {
            style: {
                width: "380px",
                "margin": "0 auto",
                "text-align": "center",
            }
        })
    ], {
        style: {
            "margin-left": "240px",
            //position: "absolute",
            //width: "100%"
        }
    })
])
mono.app(new View([
    new MonoNavigationBar("PortGuardian Auth - " + guardname),
    loginpanel,
    controlpanel
]))
var stateTimer
loadScriptBundle(["/lib/sha256.js"], () => {
    if (localStorage.getItem(pageParams + "_token") == null || localStorage.getItem(pageParams + "_account") == null) {
        logui.login()
    } else {
        logui.logout()
        controls.userident.text = "用户: " + localStorage.getItem(pageParams + "_account")
        portguardianAPI.getState()
    }
})