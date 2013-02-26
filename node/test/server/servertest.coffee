assert = require("assert")
should = require("should")
http = require("request")
redis = require("redis")
util = require("util")
crypto = require 'crypto'
dcrypt = require 'dcrypt'
async = require 'async'
fs = require("fs")
rc = redis.createClient()
port = 443
baseUri = "https://localhost:" + port

cleanup = (done) ->
  keys = [
    "users:test0",
    "users:test1",
    "users:test2",
    "friends:test0",
    "friends:test1",
    "invites:test0",
    "invited:test0",
    "invites:test1",
    "invited:test1",
    "test0:test1:id",
    "messages:test0:test1",
    "conversations:test1",
    "conversations:test0",
    "conversations:test2",
    "keytoken:test0"
    "keyversion:test0",
    "keys:test0:1",
    "keyversion:test1",
    "keys:test1:1",
    "keyversion:test2",
    "keys:test0:2"]
  rc.del keys, (err, data) ->
    if err
      done err
    else
      done()

login = (username, password, authSig, done, callback) ->
  http.post
    url: baseUri + "/login"
    json:
      username: username
      password: password
      authSig: authSig
    (err, res, body) ->
      if err
        done err
      else
        callback res, body

signup = (username, password, dhPub, dsaPub, authSig, done, callback) ->
  http.post
    url: baseUri + "/users"
    json:
      username: username
      password: password
      dhPub: dhPub
      dsaPub: dsaPub
      authSig: authSig
    (err, res, body) ->
      if err
        done err
      else
        callback res, body


generateKey = (i, callback) ->
  ecdsa = new dcrypt.keypair.newECDSA 'secp521r1'
  ecdh = new dcrypt.keypair.newECDSA 'secp521r1'

  random = crypto.randomBytes 16

  dsaPubSig =
    crypto
      .createSign('sha256')
      .update(new Buffer("test#{i}"))
      .update(new Buffer("test#{i}"))
      .update(random)
      .sign(ecdsa.pem_priv, 'base64')

  sig = Buffer.concat([random, new Buffer(dsaPubSig, 'base64')]).toString('base64')

  callback null, {
  ecdsa: ecdsa
  ecdh: ecdh
  sig: sig
  }


makeKeys = (i) ->
  return (callback) ->
    generateKey i, callback

createKeys = (number, done) ->
  keys = []
  for i in [0..number]
    keys.push makeKeys(i)

  async.parallel keys, (err, results) ->
    if err?
      done err
    else
      done null, results


describe "surespot server", () ->
  keys = undefined
  before (done) ->
    createKeys 3, (err, keyss) ->
      keys = keyss
      cleanup done

  describe "create user", () ->
    it "should respond with 201", (done) ->
      signup "test0", "test0", keys[0].ecdh.pem_pub, keys[0].ecdsa.pem_pub, keys[0].sig, done, (res, body) ->
        res.statusCode.should.equal 201
        done()

    it "and subsequently exist", (done) ->
      http.get
        url: baseUri + "/users/test0/exists",
        (err, res, body) ->
          if err
            done err
          else
            body.should.equal "true"
            done()

    #    it "even if the request case is different", (done) ->
    #      http.get
    #        url: baseUri + "/users/TEST/exists",
    #        (err,res,body) ->
    #          if err
    #            done err
    #          else
    #            body.should.equal "true"
    #            done()

    it "shouldn't be allowed to be created again", (done) ->
      signup "test0", "test0", keys[0].ecdh.pem_pub, keys[0].ecdsa.pem_pub, keys[0].sig, done, (res, body) ->
        res.statusCode.should.equal 409
        done()

  #    it "even if the request case is different", (done) ->
  #      signup "tEsT", "test", keys[0].ecdh.pem_pub, keys[0].ecdsa.pem_pub, keys[0].sig, done, (res, body) ->
  #        res.statusCode.should.equal 409
  #        done()


    it "should be able to roll the key pair", (done) ->
      kp0 = undefined
      #generate new key pairs
      generateKey 0, (err, nkp) ->
        kp0 = nkp
        http.post
          url: baseUri + "/keytoken"
          json:
            username: "test0"
            password: "test0"
            authSig: keys[0].sig
          (err, res, body) ->
            if err
              done err
            else
              console.log body
              res.statusCode.should.equal 200
              body.keyversion.should.equal 2
              body.token.should.exist
              done()
#
#    it "should not be able to login with the old signature", (done) ->
#      login "test0", "test0", keys[0].sig, done, (res, body) ->
#        res.statusCode.should.equal 401
#        done()


  describe "login with invalid password", ->
    it "should return 401", (done) ->
      login "test0", "bollocks", keys[0].sig, done, (res, body) ->
        res.statusCode.should.equal 401
        done()

  describe "login with short signature", ->
    it "should return 401", (done) ->
      login "test0", "test0", "martin", done, (res, body) ->
        res.statusCode.should.equal 401
        done()


  describe "login with invalid signature", ->
    it "should return 401", (done) ->
      login "test0", "test0", "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean venenatis dictum viverra. Duis vel justo vel purus hendrerit consequat. Duis ac nisi at ante elementum faucibus in eget lorem. Morbi cursus blandit sollicitudin. Aenean tincidunt, turpis eu malesuada venenatis, urna eros sagittis augue, et vehicula quam turpis at risus. Sed ac orci a tellus semper tincidunt eget non lorem. In porta nisi eu elit porttitor pellentesque vestibulum purus luctus. Nam venenatis porta porta. Vestibulum eget orci massa. Fusce laoreet vestibulum lacus ut hendrerit. Proin ac eros enim, ac faucibus eros. Aliquam erat volutpat.",
      done, (res, body) ->
        res.statusCode.should.equal 401
        done()

  describe "login with non existant user", ->
    it "should return 401", (done) ->
      login "your", "mama", "what kind of sig is this?", done, (res, body) ->
        res.statusCode.should.equal 401
        done()


  describe "login with valid credentials", ->
    it "should return 204", (done) ->
      login "test0", "test0", keys[0].sig, done, (res, body) ->
        res.statusCode.should.equal 204
        done()

  describe 'validate valid user', ->
    it "should return 204", (done) ->
      http.post
        url: baseUri + "/validate"
        json:
          username: 'test0'
          password: 'test0'
          authSig: keys[0].sig
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 204
            done()


  describe "invite exchange", ->
    it "created user", (done) ->
      signup "test1", "test1", keys[1].ecdh.pem_pub, keys[1].ecdsa.pem_pub, keys[1].sig, done, (res, body) ->
        res.statusCode.should.equal 201
        done()

    it "should not be allowed to invite himself", (done) ->
      http.post
        url: baseUri + "/invite/test1"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()


    it "who invites a user successfully should receive 204", (done) ->
      http.post
        url: baseUri + "/invite/test0"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 204
            done()

    it "who invites them again should receive 403", (done) ->
      http.post
        url: baseUri + "/invite/test0"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()

    it "who accepts their invite should receive 204", (done) ->
      login "test0", "test0", keys[0].sig, done, (res, body) ->
        http.post
          url: baseUri + "/invites/test1/accept"
          (err, res, body) ->
            if err
              done err
            else
              res.statusCode.should.equal 204
              done()

    it "who accepts a non existent invite should receive 404", (done) ->
      http.post
        url: baseUri + "/invites/nosuchinvite/accept"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 404
            done()


    it "who invites them again should receive a 409", (done) ->
      http.post
        url: baseUri + "/invite/test1"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 409
            done()


  describe "inviting non existent user", ->
    it "should return 404", (done) ->
      http.post
        url: baseUri + "/invites/nosuchuser"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 404
            done()


  describe "getting the public identity of a non existant user", ->
    it "should return not found", (done) ->
      http.get
        url: baseUri + "/publicidentity/nosuchuser"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 404
            done()

  describe "getting the public identity of a non friend user", ->
    it "should not be allowed", (done) ->
      signup "test2", "test2", keys[2].ecdh.pem_pub, keys[2].ecdsa.pem_pub, keys[2].sig, done, (res, body) ->
        res.statusCode.should.equal 201
        http.get
          url: baseUri + "/publickeys/test0"
          (err, res, body) ->
            if err
              done err
            else
              res.statusCode.should.equal 403
              done()

  describe "getting other user's last 30 messages", ->
    it "should not be allowed", (done) ->
      http.get
        url: baseUri + "/messages/test0"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()

  describe "getting other user's messages after x", ->
    it "should not be allowed", (done) ->
      http.get
        url: baseUri + "/messages/test0/after/0"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()

  describe "getting other user's messages before x", ->
    it "should not be allowed", (done) ->
      http.get
        url: baseUri + "/messages/test0/before/100"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()

  describe "uploading an image to a valid spot", ->
    location = undefined
    it "should return the location header and 202", (done) ->
      login "test0", "test0", keys[0].sig, done, (res, body) ->
        res.statusCode.should.equal 204
        r = http.post baseUri + "/images/1/test1/1", (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 202
            location = res.headers["location"]
            should.exists location
            done()

        form = r.form()
        form.append "image", fs.createReadStream "test"
    #todo set filename explicitly

    it "should return the same image when location url requested", (done) ->
      http.get
        url: baseUri + location
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 200
            res.body.should.equal "madman\n"
            done()

  describe "getting images from non existent spots", ->
    it "should return 404", (done) ->
      http.get
        url: baseUri + "/images/test0:test1/6000"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 404
            done()

  describe "getting images from spots we don't belong to", ->
    it "should not be allowed", (done) ->
      http.get
        url: baseUri + "/images/a:room/1"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()

  describe "uploading an image to a spot we don't belong to", ->
    it "should not be allowed", (done) ->
      login "test2", "test2", keys[2].sig, done, (res, body) ->
        res.statusCode.should.equal 204
        r = http.post baseUri + "/images/1/test1/1", (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()

        form = r.form()
        form.append "image", fs.createReadStream "test"


  #todo set filename explicitly
  after (done) -> cleanup done