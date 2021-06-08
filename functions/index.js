'use strict'
const crypto = require('crypto');
const axios = require('axios');
const functions = require("firebase-functions");
const cors = require('cors');
const express = require('express');
const helmet = require("helmet");
const admin = require("firebase-admin");
const bip39 = require('bip39');
const CryptoService = require('./bitclout/crypto.service').CryptoService;
const EntropyService = require('./bitclout/entropy.service').EntropyService;
const SigningService = require('./bitclout/signing.service');
const BackendApiService = require('./bitclout/backend-api.service');
const {promises: {readFile}} = require("fs");

const cryptoService = new CryptoService();
const entropyService = new EntropyService();
const signingService = new SigningService();
const bitcloutApiService = new BackendApiService({
    post: (endpoint, data) => {
        return axios.post(endpoint, data, {headers: {'Content-Type': 'application/json'}})
    }
});
bitcloutApiService._handleError = (e) => {
    console.log(e);
}
admin.initializeApp();
const db = admin.database();
// db.useEmulator("localhost", 9000)
//Protected functionality.

const CMPubKey = 'BC1YLfkW18ToVc1HD2wQHxY887Zv1iUZMf17QHucd6PaC3ZxZdQ6htE';
const MinFeeRateNanosPerKB = 1000;
const bitcloutEndpoint = 'bitclout.com';
var CMEndpoint, signingEndpoint;

const taskSessionsExpire = (10 * 60 * 10**3);//10 mins
const bitcloutCahceExpire = {
    'get-exchange-rate': 2 * 60 * 1000,
    'ticker': 2 * 60 * 1000,
    'get-single-profile': 24 * 60 * 60 * 1000,
    'get-app-state':  24 * 60 * 60 * 1000
}
if (process.env.NODE_ENV === 'development') {
    db.useEmulator("localhost", 9000);
    CMEndpoint = 'http://localhost:3000';
    signingEndpoint = 'http://localhost:7000';
} else {
    signingEndpoint = 'https://signing-cloutmegazord.web.app';
    CMEndpoint = 'https://cloutmegazord.web.app';
}
const app = express();
app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "script-src": ["'self'", "'unsafe-inline'", signingEndpoint],
      },
    }
  }));
app.use(cors({ origin: true }));
app.use(express.json({limit:'100kb'}))

function expireCleaner(ref) {
    ref.orderByChild('expire').once('value', async function(s) {
        if (!s.val()) {return}
        const items = s.val();
        for (let key in items) {
            let item = items[key];
            if (Date.now() > item.expire) {
                s.ref.child(key).remove();
            }
        }
    })
}

setInterval(() => {
    expireCleaner(db.ref('protected/encryptedSeeds'));
    expireCleaner(db.ref('taskSessions'));
    expireCleaner(db.ref('bitcloutCache'));
}, 2 * 60 * 1000)

async function bitcloutProxy(data) {
    return new Promise(async (resolve, reject) => {
        const action = data['action'];
        const method = data['method'] || 'post';
        var cachedData  = null;
        delete data['action']
        delete data['method']
        if (bitcloutCahceExpire[action]) {
            const cachedDataRef = await db.ref('bitcloutCache').child(JSON.stringify(data)).get();
            if (cachedDataRef.exists()) {
                console.log('Cache Hit')
                cachedData = cachedDataRef.val();
                resolve(cachedData.data);
            }
        }
        axios[method]("https://bitclout.com/api/v0/" + action,
            data,
            {headers: {'Content-Type': 'application/json'}
        }).then(resp => {
            if (bitcloutCahceExpire[action]) {
                db.ref('bitcloutCache').child(JSON.stringify({method:data})).set({
                    data: resp.data, expire: Date.now() + bitcloutCahceExpire[action]
                })
            }
            resolve(resp.data)
        }).catch(error => {
            reject(error)
        });
    })
}

async function getExchangeRate() {
    try {
        var exchangeRate = await bitcloutProxy({method: 'get', action: 'get-exchange-rate'});
        var tickerResp = await axios.get('https://blockchain.info/ticker');
      } catch (e) {
        throw new Error(e);
      }

      if (tickerResp.data.error) {
        reject(tickerResp.data.error);
      }
      var ticker = tickerResp.data;
      // var exchangeRate =  (ticker.USD.last / 100) * (exchangeRate.SatoshisPerBitCloutExchangeRate / 100000000)
      var exchangeRate =  {
        SatoshisPerBitCloutExchangeRate: exchangeRate.SatoshisPerBitCloutExchangeRate,
        USDCentsPerBitcoinExchangeRate: ticker.USD.last,
        USDbyBTCLT: ticker.USD.last * (exchangeRate.SatoshisPerBitCloutExchangeRate / 100000000)
      }
      return exchangeRate;
}

app.get('*/get', async function(req, res) {
    const taskSessionId = req.query.tid;
    const zordShrtId = req.query.zid;
    const encryptionKey = req.query.k;
    var taskSession = null;
    const taskSessionRef = await db.ref('taskSessions/' + taskSessionId).get();
    if (taskSessionRef.exists()) {
        taskSession = taskSessionRef.val();
    } else {
        res.write('Task Session not exists or expired');
        res.end();
    }
    if(!encryptionKey) {
        if (zordShrtId === taskSession.initiator.shrtId) {
            res.redirect(req.originalUrl + '&k=' + crypto.randomBytes(16).toString('hex'));
        } else {
            res.write(`Task Session already running. Ask @${taskSession.initiator.Username} for personal link.`);
        }
        return;
    }
    try {
        var template = await readFile("./templates/taskSession/task-template.html");
        var bip39_lib = await readFile("./templates/taskSession/bip39.browser.js");
        var crypto_lib = await readFile("./templates/taskSession/crypto.browser.js");
        template = template.toString();
        bip39_lib = bip39_lib.toString();
        crypto_lib = crypto_lib.toString();
    } catch (e) {
        res.write('Template reading error.');
        res.end();
    }
    template = template.replace('"%bip39.browser.js%"', bip39_lib);
    template = template.replace('"%crypto.browser.js%"', crypto_lib);
    template = template.replace('"%taskSession%"', JSON.stringify(taskSession,  null, 2));
    res.writeHeader(200, {"Content-Type": "text/html; charset=utf-8"});
    res.write(template);
    res.end();
})

// var taskSession = {
//     taskId: taskId,
//     initiator: {publicKey},
//     megazordId: data.megazordId,
//     task: dbTask,
//     readyZordsShrtIds: [],
//     endPoint: functionsUrl,
//     redirect: '/admin/tasks_list/' + data.megazordId
// }
// zord ={
//     PubKeyShort: zordId.slice(0, 14) + '...',
//     PublicKeyBase58Check: zordId,
//     shrtId: shrtId,
//     Username: profileRes.Profile.Username,
//     ProfilePic: profileRes.Profile.ProfilePic,
//     link: `/gts/${taskShrtId}&${shrtId}&${encryptionKey}`
// }

app.post('*/create', async (req, res, next) => {
    const data = req.body.data;
    var taskSession = null;
    const taskId = data.taskId;
    const taskSessionRef = await db.ref('taskSessions/' + taskId).get();
    if (taskSessionRef.exists()) {
        taskSession = taskSessionRef.val()
        if (taskSession.initiator.publicKey !== data.taskSession.initiator.publicKey) {
            res.send({data: { error: `Task Session already running. Ask ${taskSession.initiator.Username} for personal link.`}})
            return
        }
    }
    taskSession = data.taskSession;
    taskSession.expire = Date.now() + taskSessionsExpire;
    await db.ref('taskSessions').child(taskId).set(taskSession);
    res.send({ok: true});
})

app.post('*/getTaskSession', async (req, res, next) => {
    const taskId = req.data.taskId;
    const taskSessionRef = await db.ref('taskSessions/' + taskId).get();
    if (taskSessionRef.exists()) {
        taskSession = taskSessionRef.val()
        res.send({data: taskSession})
        return
    }
    res.send({data: null})
})

app.post('*/check', async (req, res, next) => {
    var {taskSessionId, zordShrtId} = req.body.data;
    const taskSessionRef = await db.ref('taskSessions/' + taskSessionId).get();
    if (!taskSessionRef.exists()) {
        res.send({data: { error: 'Taks not exists or expired.'}})
        return
    }
    var taskSession = taskSessionRef.val()
    taskSession.readyZordsShrtIds = taskSession.readyZordsShrtIds || [];
    if (taskSession.readyZordsShrtIds.length == taskSession.zords.length) {
        res.send({data: { ok: true }})
        return
    }
    if (!taskSession.readyZordsShrtIds.includes(zordShrtId)) {
        taskSession.readyZordsShrtIds.push(zordShrtId)
        db.ref('taskSessions/' + taskSessionId).child('readyZordsShrtIds').set(taskSession.readyZordsShrtIds);
    }
    res.send({data: {readyZordsShrtIds: taskSession.readyZordsShrtIds}});
});

async function finishTask(taskSessionId, task, taskData, taskError) {
    try {
        await axios.post(CMEndpoint + '/api/finishTask', {data:{task, taskData, taskError}})
    } catch (e) {
        console.log('finishTask Error: ', e)
    }
    await db.ref('protected/encryptedSeeds').child(taskSessionId).remove();
    await db.ref('taskSessions').child(taskSessionId).remove();
}

function getFee(AmountNanos, bitcloutPriceUSD) {
    var AmountNanosUSD = AmountNanos / 1e9 * bitcloutPriceUSD;
    const feesMap = {
      3: 1 * 10**4,
      2: 1 * 10**5,
      1: 1 * 10**6,
      0.5: Infinity
    }
    var fees = Object.keys(feesMap).sort().reverse();
    var trgFee = fees[0];
    for (let fee of fees) {
        let range = feesMap[fee];
        if (AmountNanosUSD < range) {
          trgFee = parseFloat(fee);
          break
        }
    }
    return AmountNanos * (trgFee / 100);
}

function zordsToMegazord(encryptedZordsEntropy, encryptionKey) {
    let length = 0;
    var zordsEntropy = [];

    for (let zordEntropy of encryptedZordsEntropy) {
        const decipher = crypto.createDecipher('aes-256-gcm', encryptionKey);
        zordEntropy = decipher.update(Buffer.from(zordEntropy, 'hex')).toString();
        if (!entropyService.isValidCustomEntropyHex(zordEntropy)) {
            throw new Error('Invalid mnemonic');
        }
        zordEntropy = Buffer.from(zordEntropy, 'hex')
        length += zordEntropy.length;
        zordsEntropy.push(zordEntropy);
    }
    let megazordEntropy = new Uint8Array(length);
    let offset = 0;
    for (let zordEntropy of zordsEntropy) {
        megazordEntropy.set(zordEntropy, offset);
        offset += zordEntropy.length;
    }
    const megazordMnemonic = bip39.entropyToMnemonic(megazordEntropy);
    try {
        if (!entropyService.isValidCustomEntropyHex(Buffer.from(megazordEntropy).toString('hex'))) {
            throw new Error('Invalid mnemonic');
        }
    } catch {
        throw new Error('Invalid mnemonic');
    }
    const keychain = cryptoService.mnemonicToKeychain(megazordMnemonic, '');
    const seedHex = cryptoService.keychainToSeedHex(keychain);
    const privateKey = cryptoService.seedHexToPrivateKey(seedHex);
    const publicKey = cryptoService.privateKeyToBitcloutPublicKey(privateKey, 'mainnet');
    return [privateKey, publicKey]
}

// Create a new array with total length and merge all source arrays.
app.post('*/run', async (req, res, next) => {
    const {taskSessionId, zordShrtId, encryptedEntropy, encryptionKey} = req.body.data;
    const taskSessionRef = await db.ref('taskSessions/' + taskSessionId).get();
    const encryptedSeedsRef = await db.ref('protected/encryptedSeeds/' + taskSessionId).get();
    var encryptedSeeds = null;
    if (!taskSessionRef.exists()) {
        res.send({data: { error: 'Taks not exists or expired.'}})
        return
    }
    const taskSession = taskSessionRef.val();
    const zordsCount = taskSession.zords.length;
    if (encryptedSeedsRef.exists()) {
        encryptedSeeds = encryptedSeedsRef.val();
    } else {
        encryptedSeeds = {
            expire: taskSession.expire,
            zordsEntropy: []
        }
    }
    encryptedSeeds.zordsEntropy = encryptedSeeds.zordsEntropy || [];
    if (encryptedSeeds.zordsEntropy.length === zordsCount) {
        res.send({data: { ok: true }});
        return
    }

    const readyZords = encryptedSeeds.zordsEntropy.map(it => it.PublicKeyBase58Check)
    for (let zord of taskSession.zords) {
        if ((zord.shrtId === zordShrtId) && !readyZords.includes(zord.PublicKeyBase58Check)) {
            encryptedSeeds.zordsEntropy.push({
                PublicKeyBase58Check: zord.PublicKeyBase58Check,
                encryptedEntropy: encryptedEntropy
            })
        }
    }

    res.send({data: { ok: true }});
    if (encryptedSeeds.zordsEntropy.length !== zordsCount) {
        await db.ref('protected/encryptedSeeds').child(taskSessionId).set(encryptedSeeds);
        return
    }
    var task = {id: taskSession.taskId, type: taskSession.task.type};
    var zordsIds = taskSession.zords.map(it => it.PublicKeyBase58Check).sort();
    var zordsEntropySignature = new Array(zordsCount);
    for (let zord of encryptedSeeds.zordsEntropy) {
        let position = zordsIds.indexOf(zord.PublicKeyBase58Check)
        zordsEntropySignature[position] = zord.encryptedEntropy
    }

    var taskError = '';
    var taskData = {megazordId:taskSession.megazordId};
    try {
        var [megazordPrivateKey, megazordPublicKey] = zordsToMegazord(zordsEntropySignature, encryptionKey);
    } catch(e) {
        taskError = 'Zord Seeds is Incorrect';
        finishTask(taskSessionId, task, taskData, taskError);
        return
    }
    if (taskSession.megazordPublicKey && megazordPublicKey !== taskSession.megazordPublicKey) {
        taskError = 'Zord Seeds is Incorrect';
        finishTask(taskSessionId, task, taskData, taskError);
        return
    }

    if (task.type === 'getPublicKey') {
        taskData.megazordPublicKey = megazordPublicKey;
    } else {
        var exchRate = await getExchangeRate();
        var AmountNanos = taskSession.task.AmountNanos;
        var feeNanos = getFee(AmountNanos, exchRate.USDbyBTCLT)
        if (task.type === 'send') {
            try {
                var sendBitCloutPreviewResp = await bitcloutApiService.SendBitCloutPreview(
                    bitcloutEndpoint,
                    taskSession.megazordPublicKey,
                    taskSession.task.Recipient,
                    AmountNanos,// - feeNanos
                    MinFeeRateNanosPerKB
                );
                const signedTransactionHex = signingService.signTransaction(
                    megazordPrivateKey,
                    sendBitCloutPreviewResp.data.TransactionHex)
                bitcloutApiService.SubmitTransaction(bitcloutEndpoint, signedTransactionHex)
            } catch (e) {
                console.log(e);
                taskError = 'Signing transaction error.';
            }
        } else {
            taskError = 'Task Not Implemented yet.';
        }
    }
    finishTask(taskSessionId, task, taskData, taskError);
    //clear seed phrases
    encryptedSeeds = {};
    zordsEntropySignature = [];
    megazordPrivateKey = null;
})

exports.taskSessions = functions.https.onRequest(app);
// exports.ts = functions.https.onRequest(async (req, res) => {
//     res.send('Page!');
//     res.end();
// });