// EXPECTED_FINDINGS: [{"primitive":"SHA1","category":"hash","line":4},{"primitive":"RSA","category":"asymmetric-cipher","line":5},{"primitive":"AES","category":"symmetric-cipher","line":6,"keySizeBits":256}]
package main
import (
    "crypto/sha1"
    "crypto/rsa"
    "crypto/aes"
)
_ = sha1.New
_ = rsa.GenerateKey
_ = aes.NewCipher
