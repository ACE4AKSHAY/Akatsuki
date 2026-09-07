// EXPECTED_FINDINGS: [{"primitive":"SHA1","category":"hash","line":3},{"primitive":"RSA","category":"asymmetric-cipher","line":4,"keySizeBits":2048},{"primitive":"AES","category":"symmetric-cipher","line":5,"keySizeBits":128,"mode":"ECB"}]
const crypto = require('crypto');
const h = crypto.createHash('sha1');
const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const c = crypto.createCipheriv('aes-128-ecb', Buffer.alloc(16), null);
