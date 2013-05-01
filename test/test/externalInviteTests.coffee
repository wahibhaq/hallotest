request = require("request")
assert = require("assert")
should = require("should")
redis = require("redis")
util = require("util")
fs = require("fs")
io = require 'socket.io-client'
crypto = require 'crypto'
dcrypt = require 'dcrypt'
async = require 'async'
rc = redis.createClient()
port = 443
baseUri = "https://localhost:" + port
jar1 = undefined
jar2 = undefined
jar3 = undefined
jar4 = undefined
cookie1 = undefined
cookie2 = undefined
cookie3 = undefined

cleanup = (done) ->
  keys = [
    "users:test0",
    "users:test1",
    "users:test2",
    "users:test3",
    "friends:test0",
    "friends:test1",
    "invites:test0",
    "invited:test0",
    "invites:test1",
    "invites:test2",
    "invites:test3",
    "invited:test1",
    "invited:test2",
    "invited:test3",
    "test0:test1:id",
    "messages:test0:test1",
    "conversations:test1",
    "conversations:test0",
    "conversations:test2",
    "keytoken:test0"
    "kv:test0",
    "keys:test0",
    "kv:test1",
    "keys:test1",
    "kv:test2",
    "keys:test2",
    "kv:test3",
    "keys:test3",
    "control:user:test0",
    "control:user:test2",
    "control:user:test1",
    "control:user:test3",
    "control:user:test3:id",
    "control:user:test1:id",
    "control:user:test0:id",
    "control:user:test2:id"]

  multi = rc.multi()

  multi.del keys
  multi.srem "users", "test0", "test1", "test2", "test3"
  multi.exec (err, results) ->
    if err
      done err
    else
      done()


login = (username, password, jar, authSig, referrers, done, callback) ->
  request.post
    url: baseUri + "/login"
    jar: jar
    json:
      username: username
      password: password
      authSig: authSig
      referrers: referrers
    (err, res, body) ->
      if err
        done err
      else
        cookie = jar.get({ url: baseUri }).map((c) -> c.name + "=" + c.value).join("; ")
        callback res, body, cookie

signup = (username, password, jar, dhPub, dsaPub, authSig, referrers, done, callback) ->
  request.post
    url: baseUri + "/users"
    jar: jar
    json:
      username: username
      password: password
      dhPub: dhPub
      dsaPub: dsaPub
      authSig: authSig
      referrers: referrers
    (err, res, body) ->
      if err
        done err
      else
        cookie = jar.get({ url: baseUri }).map((c) -> c.name + "=" + c.value).join("; ")
        callback res, body, cookie

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


describe "external invite tests", () ->
  keys = undefined
  before (done) ->
    createKeys 3, (err, keyss) ->
      keys = keyss
      cleanup done

  client = undefined
  client1 = undefined
  jsonMessage = {type: "message", to: "test0", toVersion: "1", from: "test1", fromVersion: "1", iv: 1, data: "message data", mimeType: "text/plain"}

  it 'signup with auto invite user should send invite control message to auto invite user', (done) ->
    receivedSignupResponse = false
    gotControlMessage = false
    jar1 = request.jar()
    signup 'test0', 'test0', jar1, keys[0].ecdh.pem_pub, keys[0].ecdsa.pem_pub, keys[0].sig, null, done, (res, body, cookie) ->
      client = io.connect baseUri, { 'force new connection': true}, cookie
      client.once 'connect', ->
        jar2 = request.jar()
        signup 'test1', 'test1', jar2, keys[1].ecdh.pem_pub, keys[1].ecdsa.pem_pub, keys[1].sig, JSON.stringify([{ utm_content: "test0"}]), done , (res, body, cookie) ->
          receivedSignupResponse = true
          done() if gotControlMessage

      client.once 'control', (data) ->
        receivedControlMessage = JSON.parse data
        receivedControlMessage.type.should.equal 'user'
        receivedControlMessage.action.should.equal 'invite'
        receivedControlMessage.data.should.equal 'test1'
        should.not.exist receivedControlMessage.localid
        should.not.exist receivedControlMessage.moredata
        gotControlMessage = true
        done() if receivedSignupResponse



  describe 'get friends after signup', () ->
    it 'should have user marked invited', (done) ->
      request.get
        jar: jar1
        url: baseUri + "/friends"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 200
            friendData = JSON.parse(body)
            friendData.friends[0].flags.should.equal 32
            done()

    it 'should have created an invite user control message', (done) ->
      request.get
        jar: jar1
        url: baseUri + "/latestids/0"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 200
            messageData = JSON.parse(body)

            controlData = messageData.userControlMessages
            controlData.length.should.equal 1
            receivedControlMessage = JSON.parse(controlData[0])
            receivedControlMessage.type.should.equal "user"
            receivedControlMessage.action.should.equal "invite"
            receivedControlMessage.data.should.equal "test1"
            receivedControlMessage.id.should.equal 1
            should.not.exist receivedControlMessage.moredata
            should.not.exist receivedControlMessage.from
            done()


  it 'login with auto invite user should send invite control message to auto invite user', (done) ->
    receivedSignupResponse = false
    gotControlMessage = false
    jar3 = request.jar()
    jar4 = request.jar()

    signup 'test2', 'test2', jar3, keys[2].ecdh.pem_pub, keys[2].ecdsa.pem_pub, keys[2].sig, null, done, (res, body, cookie) ->
      client2 = io.connect baseUri, { 'force new connection': true}, cookie
      client2.once 'connect', ->
        signup 'test3', 'test3', jar4, keys[3].ecdh.pem_pub, keys[3].ecdsa.pem_pub, keys[3].sig, null, done, (res, body, cookie) ->
          request.get
            jar: jar4
            url: baseUri + "/logout"
            (err, res, body) ->
              if err
                done err
              else
                login "test3", "test3", jar4, keys[3].sig, JSON.stringify([{ utm_content: "test2"}]), done, (res, body) ->
                  receivedSignupResponse = true
                  done() if gotControlMessage

      client2.once 'control', (data) ->
        receivedControlMessage = JSON.parse data
        receivedControlMessage.type.should.equal 'user'
        receivedControlMessage.action.should.equal 'invite'
        receivedControlMessage.data.should.equal 'test3'
        should.not.exist receivedControlMessage.localid
        should.not.exist receivedControlMessage.moredata
        gotControlMessage = true
        done() if receivedSignupResponse



  describe 'get friends after login', () ->
    it 'should have user marked invited', (done) ->
      request.get
        jar: jar3
        url: baseUri + "/friends"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 200
            messageData = JSON.parse(body)
            messageData.friends[0].flags.should.equal 32
            done()

    it 'should have created an invite user control message', (done) ->
      request.get
        jar: jar3
        url: baseUri + "/latestids/0"
        (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 200
            messageData = JSON.parse(body)

            controlData = messageData.userControlMessages
            controlData.length.should.equal 1
            receivedControlMessage = JSON.parse(controlData[0])
            receivedControlMessage.type.should.equal "user"
            receivedControlMessage.action.should.equal "invite"
            receivedControlMessage.data.should.equal "test3"
            receivedControlMessage.id.should.equal 1
            should.not.exist receivedControlMessage.localid
            should.not.exist receivedControlMessage.moredata
            should.not.exist receivedControlMessage.from
            done()

  after (done) ->
    client.disconnect()
    cleanup done