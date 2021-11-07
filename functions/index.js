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

axios.defaults.timeout = 5 * 60 * 1000;
const sleep = time => new Promise((r) => {setTimeout(() => r(), time)});

const bitcloutApiService = new BackendApiService({
    post: async (endpoint, data) => {
        let result = null;
        let maxAttempts = 3;
        let attempts = 0;
        let errorMessage = null;
        while (attempts < maxAttempts) {
            try {
                result = await axios.post(endpoint, data, {
                    headers: {
                        'Content-Type': 'application/json',
                        'User-Agent': BitCloutApiToken
                    }
                });                
                return result;
            } catch (e) {
                attempts += 1;
                errorMessage = e.response.data.error;
                console.log(`ApiService Error: ${errorMessage}. attempts: ${attempts}`)
                await sleep(500);
            }
        }
        throw new Error(errorMessage);
    }
});
bitcloutApiService._handleError = (e) => {
    console.log(e);
}
admin.initializeApp();
const db = admin.database();
const config = functions.config();

const BitCloutApiToken = config.bitclout ? config.bitclout.apitoken : '';
//Protected functionality.

const CMPubKey = 'BC1YLfkW18ToVc1HD2wQHxY887Zv1iUZMf17QHucd6PaC3ZxZdQ6htE';
const MinFeeRateNanosPerKB = 1000;
const bitcloutEndpoint = 'bitclout.com';
var CMEndpoint, signingEndpoint;

const bitcloutCahceExpire = {
    'get-exchange-rate': 2 * 60 * 1000,
    'ticker': 2 * 60 * 1000,
    'get-single-profile': 24 * 60 * 60 * 1000,
    'get-app-state':  24 * 60 * 60 * 1000
}

if (process.env.NODE_ENV === 'development') {
    var taskSessionsExpire = (12 * 60 * 60 * 1000);//100 mins
    db.useEmulator("localhost", 9000);
    CMEndpoint = 'http://localhost:5000';
    signingEndpoint = 'http://localhost:7000';
} else {
    var taskSessionsExpire = (12 * 60 * 60 * 1000);//10 mins
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
                    finishTask(key, {id: item.taskSession.taskId, type: item.taskSession.task.type},
                        {megazordId:item.taskSessions.megazordId}, 'Task Sessions Expires')
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
            {headers: {
                'Content-Type': 'application/json',
                'User-Agent': BitCloutApiToken
            }
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
    const taskSessionId = req.query.sid;
    const zsid = req.query.zsid;
    const taskSessionRef = await db.ref('taskSessions/' + taskSessionId).get();
    if (taskSessionRef.exists()) {
        var {taskSession, zsids} = taskSessionRef.val();
    } else {
        res.write('Task Session not exists or expired');
        res.end();
    }
    let trgZordPublicKeyBase58Check = Object.keys(zsids).reduce((cont, key) => {cont[zsids[key]] = key; return cont}, {})[zsid];
    taskSession.trgZord = Object.values(taskSession.zords).find(zord => zord.PublicKeyBase58Check === trgZordPublicKeyBase58Check)
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

app.post('/ts/create', async (req, res, next) => {
    const data = req.body.data;
    let taskSession = data.taskSession;
    let zsids = data.zsids;
    const taskSessionRef = await db.ref('taskSessions').push({taskSession, zsids, expire: Date.now() + taskSessionsExpire});
    const sessionId =  taskSessionRef.key;
    res.send({ok: true, sessionId});
});

app.post('/ts/getFee', async (req, res, next) => {
    let {AmountNanos, zords, CreatorPublicKeyBase58Check} = req.body.data;
    let exchRate = await getExchangeRate();
    let [feeNanos, feePercent, AmountUSD] = await Tasks._getFee(AmountNanos, exchRate.USDbyBTCLT, zords, CreatorPublicKeyBase58Check)
    res.send({feeNanos, feePercent, AmountUSD})
});

app.post('/ts/setPublicKeyForEncryption', async (req, res, next) => {
    var {taskSessionId, zsid, publicKeyForEncryption} = req.body.data;
    db.ref('taskSessions/' + taskSessionId).child('zordsPublicKeysForEncryption').child(zsid).set(publicKeyForEncryption);
    res.send({data: {ok: true}});
});

app.post('/ts/setEncrypedEncryptionKeys', async (req, res, next) => {
    var {taskSessionId, encrypedEncryptionKeys} = req.body.data;
    db.ref('taskSessions/' + taskSessionId).child('encrypedEncryptionKeys').set(encrypedEncryptionKeys);
    res.send({data: {ok: true}});
})

app.post('/ts/check', async (req, res, next) => {
    var {taskSessionId, zsid} = req.body.data;
    const taskSessionRef = await db.ref('taskSessions/' + taskSessionId).get();
    if (!taskSessionRef.exists()) {
        res.send({data: { error: 'Taks not exists or expired.'}})
        return
    }
    var {taskSession, zsids, zordsPublicKeysForEncryption, encrypedEncryptionKeys} = taskSessionRef.val();
    zordsPublicKeysForEncryption = zordsPublicKeysForEncryption || {};
    zsids = Object.keys(zsids).reduce((cont, key) => {cont[zsids[key]] = key; return cont}, {});
    let zords = taskSession.zords;
    let zordPublicKeyBase58Check = zsids[zsid];
    let isTrgZordInitiator = taskSession.initiator.PublicKeyBase58Check === zordPublicKeyBase58Check;
    if (isTrgZordInitiator) {
        if (Object.keys(zsids).filter(x => x in zordsPublicKeysForEncryption).length === (zords.length - 1)) {
            res.send({data: {ok: true, zordsPublicKeysForEncryption}});
            return;
        }
    } else {
        if (encrypedEncryptionKeys) {
            let encrypedEncryptionKey = encrypedEncryptionKeys[zsid];
            res.send({data: {ok: true, encrypedEncryptionKey}});
            return
        }
    }
    res.send({data: {ok: false}});
});

app.post('/ts/close', async (req, res, next) => {
    var {taskSessionId} = JSON.parse(req.body);
    const taskSessionRef = await db.ref('taskSessions/' + taskSessionId).get();
    if (!taskSessionRef.exists()) {
        res.send({data: { error: 'Taks not exists or expired.'}})
        return
    }
    var {taskSession} = taskSessionRef.val();
    // finishTask(taskSessionId, {id: taskSession.taskId, type: taskSession.task.type},
    //     {megazordId:taskSession.megazordId}, 'Task session canceled by initiator ')
    res.send({data: {ok: false}});
})

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
    async _getFee(AmountNanos, USDbyBTCLT, trgFee, CreatorPublicKeyBase58Check) {
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
        return [Math.floor(AmountNanos * (trgFee / 100)), trgFee, AmountUSD];
    },
    async _bitcloutFeeWrapper(megazordPublicKeyBase58Check, Recipient, AmountNanos) {
        let feeResp = await bitcloutApiService.SendDeSoPreview(
            bitcloutEndpoint,
            megazordPublicKeyBase58Check,
            Recipient,
            -1,
            MinFeeRateNanosPerKB
        );
        let FeeNanos = feeResp.data.FeeNanos;
        let resp = await bitcloutApiService.SendDeSoPreview(
            bitcloutEndpoint,
            megazordPublicKeyBase58Check,
            Recipient,
            AmountNanos - FeeNanos,
            MinFeeRateNanosPerKB
        );
        return resp
    },
    async sendDeSo(taskSession, exchRate, signTransaction) {
        let AmountNanos = taskSession.task.AmountNanos,
            megazordPublicKeyBase58Check = taskSession.megazordPublicKeyBase58Check,
            Recipient = taskSession.task.Recipient,
            transactionResp,
            [megazordFeeNanos, _, __] = await this._getFee(AmountNanos, exchRate.USDbyBTCLT, taskSession.trgFee);


        if (megazordFeeNanos) {
            transactionResp = await bitcloutApiService.SendDeSoPreview(
                bitcloutEndpoint,
                megazordPublicKeyBase58Check,
                Recipient,
                AmountNanos - megazordFeeNanos,
                MinFeeRateNanosPerKB
            );
        } else {
            transactionResp = await this._bitcloutFeeWrapper(megazordPublicKeyBase58Check, Recipient, AmountNanos);
        }
        let signedTransactionHex = signTransaction(transactionResp.data.TransactionHex);
        try {
            await bitcloutApiService.SubmitTransaction(bitcloutEndpoint, signedTransactionHex);
        } catch (e) {
            throw new Error("BitClout cannot process such transaction.")
        }

        if (megazordFeeNanos) {
            if (megazordFeeNanos > transactionResp.data.ChangeAmountNanos) {
                megazordFeeNanos = transactionResp.data.ChangeAmountNanos;
            }
            try {
                var FeeResp = await bitcloutApiService.SendDeSoPreview(
                    bitcloutEndpoint,
                    megazordPublicKeyBase58Check,
                    CMPubKey,
                    megazordFeeNanos - transactionResp.data.FeeNanos,
                    MinFeeRateNanosPerKB
                );
            } catch (e) {
                console.log('Megazord Fee Preview Error', e);
                return false;
            }
            let signedFeeTransactionHex = signTransaction(FeeResp.data.TransactionHex);
            try {
                bitcloutApiService.SubmitTransaction(bitcloutEndpoint, signedFeeTransactionHex);
            } catch (e) {
                console.log('Megazord Fee Transaction Error', e);
            }
        }
    },
    async sendCC(taskSession, exchRate, signTransaction) {
        let AmountNanos = taskSession.task.AmountNanos,
            megazordPublicKeyBase58Check = taskSession.megazordPublicKeyBase58Check,
            Recipient = taskSession.task.Recipient,
            CreatorPublicKeyBase58Check = taskSession.task.CreatorPublicKeyBase58Check,
            transactionResp,
            [megazordFeeNanos, _, __] = await this._getFee(AmountNanos, exchRate.USDbyBTCLT, taskSession.trgFee, taskSession.task.CreatorPublicKeyBase58Check);

        transactionResp = await bitcloutApiService.TransferCreatorCoinPreview(
            bitcloutEndpoint,
            megazordPublicKeyBase58Check,
            CreatorPublicKeyBase58Check,
            Recipient,
            AmountNanos - megazordFeeNanos,
            MinFeeRateNanosPerKB
        );
        let signedTransactionHex = signTransaction(transactionResp.data.TransactionHex);
        try {
            await bitcloutApiService.SubmitTransaction(bitcloutEndpoint, signedTransactionHex);
        } catch (e) {
            throw new Error("BitClout cannot process such transaction.")
        }
        if (megazordFeeNanos) {
            try {
                var FeeResp = await bitcloutApiService.TransferCreatorCoinPreview(
                    bitcloutEndpoint,
                    megazordPublicKeyBase58Check,
                    CreatorPublicKeyBase58Check,
                    CMPubKey,
                    megazordFeeNanos,
                    MinFeeRateNanosPerKB
                );
            } catch (e) {
                console.log('Megazord Fee Preview Error', e);
                return false;
            }
            let signedFeeTransactionHex = signTransaction(FeeResp.data.TransactionHex);
            try {
                bitcloutApiService.SubmitTransaction(bitcloutEndpoint, signedFeeTransactionHex);
            } catch (e) {
                console.log('Megazord Fee Transaction Error', e);
            }
        }
    },
    async updateProfile(taskSession, signTransaction) {
        var base64Image = "";
        if (taskSession.task.NewProfilePic) {
            var image = await axios.get(taskSession.task.NewProfilePic, {responseType: 'arraybuffer'});
            var raw = Buffer.from(image.data).toString('base64');
            var base64Image = "data:" + image.headers["content-type"] + ";base64,"+raw;
        }
        const updateResp =  await bitcloutApiService.UpdateProfilePreview(
            bitcloutEndpoint,
            // Specific fields
            taskSession.megazordPublicKeyBase58Check,
            // Optional: Only needed when updater public key != profile public key
            '',
            taskSession.task.NewUsername || "",
            taskSession.task.NewDescription || "",
            base64Image,
            taskSession.task.NewCreatorBasisPoints || "",
            1.25 * 100 * 100 /*NewStakeMultipleBasisPoints*/,
            false /*IsHidden*/,
            // End specific fields
            MinFeeRateNanosPerKB
        );
        let signedTransactionHex = signTransaction(updateResp.data.TransactionHex);
        //to avoid 403
        await sleep(1000);
        try {
            await bitcloutApiService.SubmitTransaction(bitcloutEndpoint, signedTransactionHex);
        } catch (e) {
            throw new Error("BitClout cannot process such transaction.")
        }
    },
    async repost(taskSession, signTransaction) {
        const createRepostResponse = await bitcloutApiService.Repost(bitcloutEndpoint, {
            UpdaterPublicKeyBase58Check: taskSession.megazordPublicKeyBase58Check,
            RepostedPostHashHex: taskSession.task.postHash
        });
        let signedTransactionHex = signTransaction(createRepostResponse.data.TransactionHex);
        try {
            await bitcloutApiService.SubmitTransaction(bitcloutEndpoint, signedTransactionHex);
        } catch (e) {
            throw new Error("BitClout cannot process such transaction.")
        }
    }
}

async function executeTask(taskSession, signTransaction) {
    let type = taskSession.task.type;
    try {
        if (type === 'getPublicKey') {
            return
        } else if (type == 'send') {
            var exchRate = await getExchangeRate();
            if (taskSession.task.Currency === '$DESO') {
                await Tasks.sendDeSo(taskSession, exchRate, signTransaction);
            } else {
                await Tasks.sendCC(taskSession, exchRate, signTransaction);
            }
        } else if (type == 'updateProfile') {
            await Tasks.updateProfile(taskSession, signTransaction);
        }
        else if (type == 'repost') {
            await Tasks.repost(taskSession, signTransaction);
        } else {
            throw new Error('Task type: ' + type + ' not supported');
        }
    } catch(e) {
        throw new Error(e.message);
    }
}

// Create a new array with total length and merge all source arrays.
app.post('/ts/run', async (req, res, next) => {
    const {taskSessionId, encryptedEntropy, encryptionKey, zsid} = req.body.data;
    const taskSessionRef = await db.ref('taskSessions/' + taskSessionId).get();
    const encryptedSeedsRef = await db.ref('protected/encryptedSeeds/' + taskSessionId).get();
    var encryptedSeeds = null;
    if (!taskSessionRef.exists()) {
        res.send({data: { error: 'Taks not exists or expired.'}})
        return
    }
    var {taskSession, expire, zsids} = taskSessionRef.val();
    zsids = Object.keys(zsids).reduce((cont, key) => {cont[zsids[key]] = key; return cont}, {});
    let trgZordPublicKeyBase58Check = zsids[zsid];
    const zordsCount = taskSession.zords.length;
    if (encryptedSeedsRef.exists()) {
        encryptedSeeds = encryptedSeedsRef.val();
    } else {
        encryptedSeeds = {
            expire: expire,
            zordsEntropy: []
        }
    }
    encryptedSeeds.zordsEntropy = encryptedSeeds.zordsEntropy || [];
    const readyZords = encryptedSeeds.zordsEntropy.map(it => it.PublicKeyBase58Check)
    for (let zord of taskSession.zords) {
        if ((zord.PublicKeyBase58Check === trgZordPublicKeyBase58Check)) {
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
        var [megazordPrivateKey, megazordPublicKeyBase58Check] = zordsToMegazord(zordsEntropySignature, encryptionKey);
    } catch(e) {
        taskError = 'Zord Seeds is Incorrect';
        finishTask(taskSessionId, task, taskData, taskError);
        return
    }
    if (taskSession.megazordPublicKeyBase58Check && megazordPublicKeyBase58Check !== taskSession.megazordPublicKeyBase58Check) {
        taskError = 'Zord Seeds is Incorrect';
        finishTask(taskSessionId, task, taskData, taskError);
        return
    }
    taskData.megazordPublicKeyBase58Check = megazordPublicKeyBase58Check;
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
