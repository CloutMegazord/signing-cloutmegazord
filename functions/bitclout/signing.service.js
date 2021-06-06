// import { Injectable } from '@angular/core';
// import KeyEncoder from 'key-encoder';
// import * as jsonwebtoken from 'jsonwebtoken';
// import * as ecies from '../lib/ecies';
// import {CryptoService} from './crypto.service';
const sha256 = require('sha256');

const uvarint64ToBuf = (uint) => {
  const result = [];

  while (uint >= 0x80) {
    result.push((uint & 0xFF) | 0x80);
    uint >>>= 7;
  }

  result.push(uint | 0);

  return new Buffer(result);
};

class SigningService {

  constructor() { }

  signJWT(seedHex) {
    const keyEncoder = new KeyEncoder('secp256k1');
    const encodedPrivateKey = keyEncoder.encodePrivate(seedHex, 'raw', 'pem');
    return jsonwebtoken.sign({ }, encodedPrivateKey, { algorithm: 'ES256', expiresIn: 60 });
  }

  decryptMessages(seedHex, encryptedHexes) {
    const privateKey = this.cryptoService.seedHexToPrivateKey(seedHex);
    const privateKeyBuffer = privateKey.getPrivate().toBuffer();

    const decryptedHexes = {};
    for (const encryptedHex of encryptedHexes) {
      const encryptedBytes = new Buffer(encryptedHex, 'hex');
      try {
        decryptedHexes[encryptedHex] = ecies.decrypt(privateKeyBuffer, encryptedBytes);;
      } catch (e) {
        console.error(e);
      }
    }

    return decryptedHexes;
  }

  signTransaction(privateKey, transactionHex) {
    const transactionBytes = new Buffer(transactionHex, 'hex');
    const transactionHash = new Buffer(sha256.x2(transactionBytes), 'hex');
    const signature = privateKey.sign(transactionHash);
    const signatureBytes = new Buffer(signature.toDER());
    const signatureLength = uvarint64ToBuf(signatureBytes.length);

    const signedTransactionBytes = Buffer.concat([
      // This slice is bad. We need to remove the existing signature length field prior to appending the new one.
      // Once we have frontend transaction construction we won't need to do this.
      transactionBytes.slice(0, -1),
      signatureLength,
      signatureBytes,
    ]);

    return signedTransactionBytes.toString('hex');
  }

  signBurn(seedHex, unsignedHashes) {
    const privateKey = this.cryptoService.seedHexToPrivateKey(seedHex);
    const signedHashes = [];

    for (const unsignedHash of unsignedHashes) {
      const signature = privateKey.sign(unsignedHash);
      const signatureBytes = new Buffer(signature.toDER());
      signedHashes.push(signatureBytes.toString('hex'));
    }

    return signedHashes;
  }
}

module.exports = SigningService;