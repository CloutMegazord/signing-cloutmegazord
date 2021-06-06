const HDKey = require('hdkey');
const bip39 = require('bip39');
const EC = require('elliptic').ec;
const bs58check = require('bs58check');
const crypto = require('crypto');
// import {CookieService} from 'ngx-cookie';
// import {AccessLevel, Network} from '../types/identity';
const {createHmac, createCipher, createDecipher, randomBytes} = crypto;

const CryptoService = class {
  constructor() { }

  static PUBLIC_KEY_PREFIXES = {
    mainnet: {
      bitcoin: [0x00],
      bitclout: [0xcd, 0x14, 0x0],
    },
    testnet: {
      bitcoin: [0x6f],
      bitclout: [0x11, 0xc2, 0x0],
    }
  };

  // Safari only lets us store things in cookies
  mustUseStorageAccess() {
    return typeof document.hasStorageAccess === 'function';
  }

  // 32 bytes = 256 bits is plenty of entropy for encryption
  newEncryptionKey() {
    return randomBytes(32).toString('hex');
  }

  seedHexEncryptionStorageKey(hostname) {
    return `seed-hex-key-${hostname}`;
  }

  hasSeedHexEncryptionKey(hostname) {
    const storageKey = this.seedHexEncryptionStorageKey(hostname);

    if (this.mustUseStorageAccess()) {
      return !!this.cookieService.get(storageKey);
    } else {
      return !!localStorage.getItem(storageKey);
    }
  }

  seedHexEncryptionKey(hostname) {
    const storageKey = this.seedHexEncryptionStorageKey(hostname);
    let encryptionKey;

    if (this.mustUseStorageAccess()) {
      encryptionKey = this.cookieService.get(storageKey);
      if (!encryptionKey) {
        encryptionKey = this.newEncryptionKey();
        this.cookieService.put(storageKey, encryptionKey, {
          expires: new Date('2100/01/01 00:00:00'),
        });
      }
    } else {
      encryptionKey = localStorage.getItem(storageKey) || '';
      if (!encryptionKey) {
        encryptionKey = this.newEncryptionKey();
        localStorage.setItem(storageKey, encryptionKey);
      }
    }

    // If the encryption key is unset or malformed we need to stop
    // everything to avoid returning unencrypted information.
    if (!encryptionKey || encryptionKey.length !== 64) {
      throw new Error('Failed to load or generate encryption key; this should never happen');
    }

    return encryptionKey;
  }

  encryptSeedHex(seedHex, hostname) {
    const encryptionKey = this.seedHexEncryptionKey(hostname);
    const cipher = createCipher('aes-256-gcm', encryptionKey);
    return cipher.update(seedHex).toString('hex');
  }

  decryptSeedHex(encryptedSeedHex, hostname) {
    const encryptionKey = this.seedHexEncryptionKey(hostname);
    const decipher = createDecipher('aes-256-gcm', encryptionKey);
    return decipher.update(Buffer.from(encryptedSeedHex, 'hex')).toString();
  }

  accessLevelHmac(accessLevel, seedHex) {
    const hmac = createHmac('sha256', seedHex);
    return hmac.update(accessLevel.toString()).digest().toString('hex');
  }

  validAccessLevelHmac(accessLevel, seedHex, hmac) {
    if (!hmac || !seedHex) {
      return false;
    }

    return hmac === this.accessLevelHmac(accessLevel, seedHex);
  }

  encryptedSeedHexToPrivateKey(encryptedSeedHex, domain) {
    const seedHex = this.decryptSeedHex(encryptedSeedHex, domain);
    return this.seedHexToPrivateKey(seedHex);
  }

  mnemonicToKeychain(mnemonic, extraText, nonStandard) {
    const seed = bip39.mnemonicToSeedSync(mnemonic, extraText);
    // @ts-ignore
    return HDKey.fromMasterSeed(seed).derive('m/44\'/0\'/0\'/0/0', nonStandard);
  }

  keychainToSeedHex(keychain) {
    return keychain.privateKey.toString('hex');
  }

  seedHexToPrivateKey(seedHex) {
    const ec = new EC('secp256k1');
    return ec.keyFromPrivate(seedHex);
  }

  privateKeyToBitcloutPublicKey(privateKey, network) {
    const prefix = CryptoService.PUBLIC_KEY_PREFIXES[network].bitclout;
    const key = privateKey.getPublic().encode('array', true);
    const prefixAndKey = Uint8Array.from([...prefix, ...key]);

    return bs58check.encode(prefixAndKey);
  }

  keychainToBtcAddress(keychain, network) {
    const prefix = CryptoService.PUBLIC_KEY_PREFIXES[network].bitcoin;
    // @ts-ignore TODO: add "identifier" to type definition
    const identifier = keychain.identifier;
    const prefixAndKey = Uint8Array.from([...prefix, ...identifier]);

    return bs58check.encode(prefixAndKey);
  }
}

exports.CryptoService = CryptoService;