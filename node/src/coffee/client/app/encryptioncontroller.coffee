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
      @privatekey = localStorage.getItem("privatekey")
      if @privatekey
        console.log "keypair loaded from localStorage"
        @_setAsymKey JSON.parse(@privatekey)

        #if we have a callback, call it
        #the consumer should check if the publickey is available before setting the callback
        @readycallback true if @readycallback
      else

        #new user so start generating a key asynchronously, maybe by the time they're done
        #entering login stuff the key will be ready
        encryption.generateKeyPairAsync (generatedKey) =>
          console.log "keypair generated"

          #dump this in localstorage for now
          localStorage.setItem "privatekey", JSON.stringify(generatedKey)
          @_setAsymKey generatedKey
          @readycallback true if @readycallback


    _hydratePublicKey: (username, callback) ->
      publickey = @publickeys[username]
      if publickey?
        callback(publickey)
      else
        networkcontroller.getPublicKey username, (publickey) =>
          @_storePublicKey username, publickey
          callback publickey
        , ->
          callback null




    #cache the public key for a user
    _storePublicKey: (username, publickey) ->
      @publickeys[username] = publickey

    asymDecrypt: (ciphertext) ->
      encryption.asymDecrypt @privatekey, ciphertext

    createSymKeys: (room, remoteusername, callback) ->
      @_hydratePublicKey remoteusername, (remotepublickey) =>
        unless remotepublickey?
          alert "no public key!"
          callback null

        #todo autogen sym key
        #todo don't store in plain text
        newKey = "somekey"
        @symmetricKeys[room] = newKey
        mkey = encryption.rsaEncrypt(@publickey, newKey)
        tkey = encryption.rsaEncrypt(remotepublickey, newKey)
        callback {
          mykey: mkey,
          theirkey: tkey
        }

    symEncrypt: (room, plaintext) ->
      return encryption.aesEncrypt(@symmetricKeys[room], plaintext)

    symDecrypt: (room, ciphertext) ->
      return encryption.aesDecrypt(@symmetricKeys[room], ciphertext)


    _setAsymKey: (key) ->
      @privatekey = key
      @publickey = key.n

  return new EncryptionController()
  


