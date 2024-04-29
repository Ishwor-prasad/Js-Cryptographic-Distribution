const { subtle } = require("crypto").webcrypto;
const crypto = require("crypto");
const { encode, decode } = require("./lib");
const { error } = require("console");

class KeyChain {
  constructor(key, kvs) {
    this.kvs = kvs;
    this.key = key;
  }

  static async encryptValue(value, KEY) {
    const iv = crypto.randomBytes(12);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      KEY,
      encode(value)
    );
    // return ciphertext;
    return { iv: iv.toString("hex"), ciphertext };
  }

  static async decryptValue(ciphertext, KEY) {
    const iv = ciphertext.iv;
    const encryptedData = ciphertext.ciphertext;
    const decryptedData = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: Buffer.from(iv, "hex") },
      KEY,
      encryptedData
    );
    return decode(decryptedData);
  }

  static async getKey(keyData) {
    // Implement key retrieval logic here
  }

  async set(domain, password) {
    const ciphertext = await KeyChain.encryptValue(password, this.key);
    const hashedDomain = await KeyChain.computeHMAC(domain, this.key);
    this.kvs[hashedDomain] = ciphertext;
  }

  async get(domain) {
    const hashedDomain = await KeyChain.computeHMAC(domain, this.key);

    const ciphertext = this.kvs[hashedDomain];
    if (!ciphertext) return null;
    const plaintext = await KeyChain.decryptValue(ciphertext, this.key);
    return plaintext;
  }

  async remove(domain) {
    try {
      const hashedDomain = await KeyChain.computeHMAC(domain, this.key);
      delete this.kvs[hashedDomain];
      return true;
    } catch (error) {
      return false;
    }
  }

  static async computeHMAC(data, key) {
    const hmac = crypto.createHmac("sha256", key);
    hmac.update(data);
    return hmac.digest("hex");
  }
}

module.exports = KeyChain;
