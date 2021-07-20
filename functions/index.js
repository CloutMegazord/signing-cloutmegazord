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
//Protected functionality.

const CMPubKey = 'BC1YLfkW18ToVc1HD2wQHxY887Zv1iUZMf17QHucd6PaC3ZxZdQ6htE';
const MinFeeRateNanosPerKB = 1000;
const bitcloutEndpoint = 'bitclout.com';
var CMEndpoint, signingEndpoint;

const bitcloutCahceExpire = {
    'get-exchange-rate': 2 * 60 * 1000,
    'ticker': 2 * 60 * 1000,
    'get-single-profile': 24 * 60 * 60 * 1000,
    'get-app-state':  24 * 60 * 60 * 1000,
    'get-users-stateless': 1 * 60 * 1000
}

if (process.env.NODE_ENV === 'development') {
    var taskSessionsExpire = (100 * 60 * 1000);//100 mins
    db.useEmulator("localhost", 9000);
    CMEndpoint = 'http://localhost:5000';
    signingEndpoint = 'http://localhost:7000';
} else {
    var taskSessionsExpire = (10 * 60 * 1000);//10 mins
    signingEndpoint = 'https://signing-cloutmegazord.web.app';
    CMEndpoint = 'https://cloutmegazord.web.app';
}

const FeesMap = {
    1.5: 1 * 10**4,
    1: 1 * 10**5,
    0.5: Infinity
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

function expireCleaner(ref, name) {
    ref.orderByChild('expire').once('value', async function(s) {
        if (!s.val()) {return}
        const items = s.val();
        for (let key in items) {
            let item = items[key];
            if (Date.now() > item.expire) {
                if(name === 'taskSessions') {
                    finishTask(item.taskId, {id: item.taskId, type: item.task.type},
                        {megazordId:item.megazordId}, 'Task Sessions Expires')
                } else {
                    s.ref.child(key).remove();
                }
            }
        }
    })
}
setInterval(() => {
    // expireCleaner(db.ref('protected/encryptedSeeds'), 'protected/encryptedSeeds');
    expireCleaner(db.ref('taskSessions'), 'taskSessions');
    expireCleaner(db.ref('bitcloutCache'), 'bitcloutCache');
}, 2 * 60 * 1000)

async function bitcloutProxy(data) {
    return new Promise(async (resolve, reject) => {
        const action = data['action'];
        const method = data['method'] || 'post';
        var cachedData  = null;
        delete data['action']
        delete data['method']
        if (bitcloutCahceExpire[action]) {
            const cachedDataRef = await db.ref('bitcloutCache').child(JSON.stringify({[method]:data})).get();
            if (cachedDataRef.exists()) {
                console.log('Cache Hit')
                cachedData = cachedDataRef.val();
                resolve(cachedData.data);
                return
            }
        }
        axios[method]("https://bitclout.com/api/v0/" + action,
            data,
            {headers: {'Content-Type': 'application/json'}
        }).then(resp => {
            if (action === 'get-single-profile') {
                resp.data.Profile.ProfilePic = 'https://bitclout.com/api/v0/get-single-profile-picture/' + resp.data.Profile.PublicKeyBase58Check;
            }
            if (bitcloutCahceExpire[action]) {
                db.ref('bitcloutCache').child(JSON.stringify({[method]:data})).set({
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
      } catch (e) {
        throw new Error(e);
      }
      var exchangeRate =  {
        SatoshisPerBitCloutExchangeRate: exchangeRate.SatoshisPerBitCloutExchangeRate,
        USDCentsPerBitcoinExchangeRate: exchangeRate.USDCentsPerBitcoinExchangeRate,
        USDbyBTCLT: exchangeRate.USDCentsPerBitCloutExchangeRate / 100
      }
      return exchangeRate;
}

app.get('/ts/get', async function(req, res) {
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

app.post('/ts/create', async (req, res, next) => {
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
    res.send({ok: true, expire: taskSession.expire});
});

app.post('/ts/getTaskSession', async (req, res, next) => {
    const taskId = req.data.taskId;
    const taskSessionRef = await db.ref('taskSessions/' + taskId).get();
    if (taskSessionRef.exists()) {
        taskSession = taskSessionRef.val()
        res.send({data: taskSession})
        return
    }
    res.send({data: null})
});

app.post('/ts/getFee', async (req, res, next) => {
    let {AmountNanos, zords, CreatorPublicKeyBase58Check} = req.body.data;
    let exchRate = await getExchangeRate();
    let [feeNanos, feePercent, AmountUSD] = await Tasks._getFee(AmountNanos, exchRate.USDbyBTCLT, zords, CreatorPublicKeyBase58Check)
    res.send({feeNanos, feePercent, AmountUSD})
});

app.post('/ts/check', async (req, res, next) => {
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
    await db.ref('protected/encryptedSeeds').child(taskSessionId).remove();
    await db.ref('taskSessions').child(taskSessionId).remove();
    try {
        await axios.post(CMEndpoint + '/api/finishTask', {data:{task, taskData, taskError}})
    } catch (e) {
        console.log('finishTask Error: ', e.message)
    }
}

function zordsToMegazord(encryptedZordsEntropy, encryptionKey) {
    let length = 0;
    let maxLength = 32;
    var zordsEntropyBytes = [];
    let zordsCount = encryptedZordsEntropy.length;
    var megazordMnemonic;
    const zordsEntropy = encryptedZordsEntropy.map(encryptedZordEntropy => {
        const decipher = crypto.createDecipher('aes-256-gcm', encryptionKey);
        return decipher.update(Buffer.from(encryptedZordEntropy, 'hex')).toString()
    });
    //If the total entropy length is not divided at 32 we should choose which Zord will have short seed length.
    let shortZordEntropy = [...zordsEntropy].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()))[0];
    let shortZordId = zordsEntropy.indexOf(shortZordEntropy);
    for (let zordId = 0;  zordId < zordsEntropy.length; zordId += 1) {
        let zordEntropyHex = zordsEntropy[zordId];
        if (!entropyService.isValidCustomEntropyHex(zordEntropyHex) && (zordEntropyHex.length === 32)) {
            throw new Error('Invalid mnemonic');
        }
        let zordEntropyBytes = Buffer.from(zordEntropyHex, 'hex')
        //Handle case with 3+ owners
        if (zordsEntropy.length > 2) {
            let avgLength = maxLength / zordsCount;
            avgLength = (zordId === shortZordId) ? Math.floor(avgLength) : Math.ceil(avgLength);
            let _zordEntropyBytes = [];
            // we can't use 32+ bytes for mnemonic and should reduce the size of the seedphrase as safely as possible
            for (let byte of zordEntropyBytes) {
                let index = byte % zordEntropyBytes.length;
                //The positions of the used bits are calculated from the seedphrase bits.
                _zordEntropyBytes.push(zordEntropyBytes[index]);
                if (_zordEntropyBytes.length === avgLength) {
                    break;
                }
            }
            zordEntropyBytes = _zordEntropyBytes;
        }
        length += zordEntropyBytes.length;
        if (length > maxLength) {
            zordEntropyBytes = zordEntropyBytes.slice(0, zordEntropyBytes.length - (length - maxLength))
            length = maxLength;
        }
        zordsEntropyBytes.push(zordEntropyBytes);
    }
    let megazordEntropy = new Uint8Array(length);
    let offset = 0;
    for (let zordEntropyBytes of zordsEntropyBytes) {
        megazordEntropy.set(zordEntropyBytes, offset);
        offset += zordEntropyBytes.length;
    }
    megazordMnemonic = bip39.entropyToMnemonic(megazordEntropy);

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

const Tasks = {
    async _getFee(AmountNanos, USDbyBTCLT, zords, CreatorPublicKeyBase58Check) {
        let AmountUSD;
        if (CreatorPublicKeyBase58Check) {
            let userResp = await bitcloutProxy({
                action: 'get-users-stateless',
                PublicKeysBase58Check: [CreatorPublicKeyBase58Check],
                SkipForLeaderboard: true
            });
            let CoinPriceBitCloutNanos = userResp.UserList[0].ProfileEntryResponse.CoinPriceBitCloutNanos;
            AmountUSD = (AmountNanos / 1e9) * (CoinPriceBitCloutNanos / 1e9 ) * USDbyBTCLT;
        } else {
            AmountUSD = AmountNanos / 1e9 * USDbyBTCLT;
        }
        let customFees;
        var trgFee;
        let customFeesSnap = await db.ref('customFee').get();
        if (customFeesSnap.exists()) {
            customFees = customFeesSnap.val();
        } else {
            customFees = {};
        }
        for (let zord of zords) {
            if (customFees[zord] !== undefined) {
                if (trgFee === undefined) {
                    trgFee = customFees[zord];
                } else {
                    trgFee = (trgFee < customFees[zord]) ? trgFee : customFees[zord];
                }
            }
        }
        if (trgFee === undefined) {
            var fees = Object.keys(FeesMap).sort().reverse();
            trgFee = fees[0];
            for (let fee of fees) {
                let range = FeesMap[fee];
                if (AmountUSD < range) {
                    trgFee = parseFloat(fee);
                    break
                }
            }
        }
        return [Math.floor(AmountNanos * (trgFee / 100)), trgFee, AmountUSD];
    },
    async _bitcloutFeeWrapper(megazordPublicKey, Recipient, AmountNanos) {
        let feeResp = await bitcloutApiService.SendBitCloutPreview(
            bitcloutEndpoint,
            megazordPublicKey,
            Recipient,
            -1,
            MinFeeRateNanosPerKB
        );
        let FeeNanos = feeResp.data.FeeNanos;
        let resp = await bitcloutApiService.SendBitCloutPreview(
            bitcloutEndpoint,
            megazordPublicKey,
            Recipient,
            AmountNanos - FeeNanos,
            MinFeeRateNanosPerKB
        );
        return resp
    },
    async sendCLOUT(taskSession, exchRate, signTransaction) {
        var zordsIds = taskSession.zords.map(it => it.PublicKeyBase58Check)
        let AmountNanos = taskSession.task.AmountNanos,
            megazordPublicKey = taskSession.megazordPublicKey,
            Recipient = taskSession.task.Recipient,
            transactionResp,
            [megazordFeeNanos, _, __] = await this._getFee(AmountNanos, exchRate.USDbyBTCLT, zordsIds);

        if (megazordFeeNanos) {
            transactionResp = await bitcloutApiService.SendBitCloutPreview(
                bitcloutEndpoint,
                megazordPublicKey,
                Recipient,
                AmountNanos - megazordFeeNanos,
                MinFeeRateNanosPerKB
            );
        } else {
            transactionResp = await this._bitcloutFeeWrapper(megazordPublicKey, Recipient, AmountNanos);
        }
        let signedTransactionHex = signTransaction(transactionResp.data.TransactionHex);
        try {
            await bitcloutApiService.SubmitTransaction(bitcloutEndpoint, signedTransactionHex);
        } catch (e) {
            throw new Error("BitClout cannot process such transaction.")
        }

        if (megazordFeeNanos) {
            console.log('megazordFeeNanos', megazordFeeNanos);
            console.log('ChangeAmountNanos', transactionResp.data.ChangeAmountNanos)
            if (megazordFeeNanos > transactionResp.data.ChangeAmountNanos) {
                megazordFeeNanos = transactionResp.data.ChangeAmountNanos;
            }
            let FeeResp = await bitcloutApiService.SendBitCloutPreview(
                bitcloutEndpoint,
                megazordPublicKey,
                CMPubKey,
                megazordFeeNanos - transactionResp.data.FeeNanos,
                MinFeeRateNanosPerKB
            );
            let signedFeeTransactionHex = signTransaction(FeeResp.data.TransactionHex);
            try {
                bitcloutApiService.SubmitTransaction(bitcloutEndpoint, signedFeeTransactionHex);
            } catch (e) {
                console.log(e);
            }
        }
    },
    async sendCC(taskSession) {
        let AmountNanos = taskSession.task.AmountNanos;
        let [feeNanos, _, __] = await this._getFee(
            AmountNanos,
            taskSession.zords, exchRate.USDbyBTCLT,
            taskSession.task.CreatorPublicKeyBase58Check);

        let transactionResp = await bitcloutApiService.TransferCreatorCoinPreview(
            bitcloutEndpoint,
            taskSession.megazordPublicKey,
            taskSession.task.CreatorPublicKeyBase58Check,
            taskSession.task.Recipient,
            AmountNanos - feeNanos,
            MinFeeRateNanosPerKB
        );
        let transactionHex = transactionResp.data.TransactionHex;
        let feeTransactionHex;
        if (feeNanos) {
            FeeResp = await bitcloutApiService.TransferCreatorCoinPreview(
                bitcloutEndpoint,
                taskSession.megazordPublicKey,
                taskSession.task.CreatorPublicKeyBase58Check,
                taskSession.task.Recipient,
                feeNanos,
                MinFeeRateNanosPerKB
            );
            feeTransactionHex = FeeResp.data.TransactionHex;
        }

        return [transactionHex, feeTransactionHex];
    },
    async updateProfile(taskSession) {
        const transactionResp =  await bitcloutApiService.UpdateProfilePreview(
            bitcloutEndpoint,
            // Specific fields
            taskSession.megazordPublicKey,
            // Optional: Only needed when updater public key != profile public key
            '',
            taskSession.task.NewUsername,
            taskSession.task.NewDescription,
            taskSession.task.NewProfilePic,
            taskSession.task.NewCreatorBasisPoints,
            1.25 * 100 * 100 /*NewStakeMultipleBasisPoints*/,
            false /*IsHidden*/,
            // End specific fields
            MinFeeRateNanosPerKB
        );
        let transactionHex = transactionResp.data.TransactionHex;
        return [transactionHex, undefined]
    }
}

async function executeTask(taskSession, signTransaction) {
    let type = taskSession.task.type;
    try {
        if (type === 'getPublicKey') {
            return
        } else if (type == 'send') {
            var exchRate = await getExchangeRate();
            if (taskSession.task.Currency === '$ClOUT') {
                await Tasks.sendCLOUT(taskSession, exchRate, signTransaction);
            } else {
                [transactionHex, feeTransactionHex] = await Tasks.sendCC(taskSession, exchRate, signTransaction);
            }
        } else if (task.type == 'updateProfile') {
            [transactionHex, feeTransactionHex] = await Tasks.updateProfile(updateProfile);
        }
    } catch(e) {
        throw new Error(e.message);
    }
}

// Create a new array with total length and merge all source arrays.
app.post('/ts/run', async (req, res, next) => {
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
    const readyZords = encryptedSeeds.zordsEntropy.map(it => it.PublicKeyBase58Check)
    for (let zord of taskSession.zords) {
        if ((zord.shrtId === zordShrtId)) {
            if (readyZords.includes(zord.PublicKeyBase58Check)) {
                encryptedSeeds.zordsEntropy[readyZords.indexOf(zord.PublicKeyBase58Check)] = {
                    PublicKeyBase58Check: zord.PublicKeyBase58Check,
                    encryptedEntropy: encryptedEntropy
                }
            } else {
                encryptedSeeds.zordsEntropy.push({
                    PublicKeyBase58Check: zord.PublicKeyBase58Check,
                    encryptedEntropy: encryptedEntropy
                })
            }
        }
    }

    res.send({data: { ok: true }});
    if (encryptedSeeds.zordsEntropy.length !== zordsCount) {
        await db.ref('protected/encryptedSeeds').child(taskSessionId).set(encryptedSeeds);
        return
    }
    var task = {id: taskSession.taskId, type: taskSession.task.type};
    var zordsIds = taskSession.zords.map(it => it.PublicKeyBase58Check)
        .sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
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
    taskData.megazordPublicKey = megazordPublicKey;
    const signTransaction = tx => {
        try {
            return signingService.signTransaction(megazordPrivateKey, tx);
        } catch (e) {
            throw new Error('Sign Transaction Error');
        }
    };
    try {
        await executeTask(taskSession, signTransaction);
    } catch (e) {
        taskError = e.message;
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