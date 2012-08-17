define ->
  generateEccKeyPairAsync: (result) ->
    keys = sjcl.ecc.elGamal.generateKeys(384, 6)
    result keys


  generateRsaKeyPairAsync: (result) ->
    key = new RSAKey()
    key.generateAsync 256, "03", ->
      privatekey =
        n: linebrk(key.n.toString(16), 64)
        d: linebrk(key.d.toString(16), 64)
        p: linebrk(key.p.toString(16), 64)
        q: linebrk(key.q.toString(16), 64)
        dmp1: linebrk(key.dmp1.toString(16), 64)
        dmq1: linebrk(key.dmq1.toString(16), 64)
        coeff: linebrk(key.coeff.toString(16), 64)

      result privatekey

  eccEncrypt: (publickey, plaintext) ->
    sjcl.encrypt publickey, plaintext

  eccDecrypt: (privatekey, ciphertext) ->
    sjcl.decrypt privatekey, ciphertext

  rsaEncrypt: (publickey, plaintext) ->
    rsa = new RSAKey()
    rsa.setPublic publickey, "03"
    rsa.encrypt plaintext

  rsaDecrypt: (privatekey, ciphertext) ->
    rsa = new RSAKey()
    rsa.setPrivateEx privatekey.n, "03", privatekey.d, privatekey.p, privatekey.q, privatekey.dmp1, privatekey.dmq1, privatekey.coeff
    rsa.decrypt ciphertext

  aesEncrypt: (password, plaintext) ->
    sjcl.encrypt password, plaintext,
      ks: 256


  aesDecrypt: (password, ciphertext) ->
    sjcl.decrypt password, ciphertext

