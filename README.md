# PortGuardian
A port filter web application,<br/>
which combined of two parts: filter api based on rules of iptables,<br/>
user interface based on Mono.js Web Framework: https://github.com/jlywxy/mono.js<br/><br/>
Current version: 
api 1.01, mono.js ui 1.2, mono.js 22axdc<br/>
Author: jlywxy https://github.com/jlywxy, jlywxy@outlook.com
## Usage
### Prerequisites
`node.js` current version (v16; old version not tested.)
`Mono.js` version 22axdc or newer(not tested)
### deploy api backend
* pre-define users and admins in `pgdb.json`, which formats are shown in `pgdb-default.json`
* install npm packages:
`npm install eccrypto`
* make sure `pgdb.json` and `index.js` are in the same dir, then run `sudo node index.js`
### deploy UI frontend
* deploy Mono.js to a http server https://github.com/jlywxy/mono.js
* copy portguardianmc.monoapp.js to a desired path beyond server root.

## Achievement
PortGuardian works well with Minecraft servers running on the Internet without opening "online-mode" and worrying about unauthorized access, which not only controls connections but supervise the status of server.