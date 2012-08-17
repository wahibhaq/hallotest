define ["./encryption", "./networkcontroller"], (encryption, networkcontroller) ->
  class EncryptionController
    symmetricKeys:
      {}
    publickeys:
      {}
    privatekey: null
    publickey: null
    readycallback: null

    constructor: ->
      #todo check if key is on disk
      # return true;
      #  localStorage.clear();
      key = localStorage.getItem("privatekey")
      if key?
        console.log "keypair loaded from localStorage"
        @_rebuildKeys JSON.parse(key)

      if not sjcl.random.isReady()
        console.log "starting random collection, move the mouse"
        #start with some random shit
        sjcl.random.startCollectors()
        sjcl.random.addEventListener "seeded", =>
          console.log 'random ready'
          sjcl.random.stopCollectors()
          if @privatekey?
            @readycallback true if @readycallback?
          else
            @_generateKeyPair()
      else
        console.log "random ready"
        if @privatekey?
          @readycallback true if @readycallback?
        else
          @_generateKeyPair()



    _generateKeyPair: () ->
      #new user so start generating a key asynchronously, maybe by the time they're done
      #entering login stuff the key will be ready
      encryption.generateEccKeyPairAsync (generatedKey) =>
        console.log "keypair generated"

        #dump this in localstorage for now
        localStorage.setItem "privatekey", JSON.stringify { pub: generatedKey.pub.serialize(), sec: generatedKey.sec.serialize()}
        @privatekey = generatedKey.sec
        @publickey = generatedKey.pub
        @readycallback true if @readycallback and sjcl.random.isReady()

    _hydratePublicKey: (username, callback) ->
      publickey = @publickeys[username]
      if publickey?
        callback(publickey)
      else
        networkcontroller.getPublicKey username, (publickey) =>
          key = @_rebuildPublicKey(JSON.parse(publickey))
          @_storePublicKey username, key
          callback key
        , ->
          callback null




    #cache the public key for a user
    _storePublicKey: (username, publickey) ->
      @publickeys[username] = publickey

    asymDecrypt: (ciphertext) ->
      encryption.eccDecrypt @privatekey, ciphertext

    createSymKeys: (room, remoteusername, callback) ->
      @_hydratePublicKey remoteusername, (remotepublickey) =>
        unless remotepublickey?
          alert "no public key!"
          callback null

        #todo autogen sym key
        #todo don't store in plain text
        newKey = "somekey"
        @symmetricKeys[room] = newKey
        mkey = encryption.eccEncrypt(@publickey, newKey)
        tkey = encryption.eccEncrypt(remotepublickey, newKey)
        callback {
          mykey: mkey,
          theirkey: tkey
        }

    symEncrypt: (room, plaintext) ->
      return encryption.aesEncrypt(@symmetricKeys[room], plaintext)

    symDecrypt: (room, ciphertext) ->
      return encryption.aesDecrypt(@symmetricKeys[room], ciphertext)


    _rebuildKeys: (key) ->

      point = sjcl.ecc.curves['c'+key.pub.curve].fromBits(key.pub.point)
      ex = sjcl.bn.fromBits key.sec.exponent

      @privatekey = new sjcl.ecc.elGamal.secretKey key.sec.curve, sjcl.ecc.curves['c' + key.sec.curve], ex
      @publickey = new sjcl.ecc.elGamal.publicKey key.pub.curve, point.curve, point

    _rebuildPublicKey: (key) ->
      point = sjcl.ecc.curves['c'+key.curve].fromBits(key.point)
      return new sjcl.ecc.elGamal.publicKey key.curve, point.curve, point


  return new EncryptionController()
  


