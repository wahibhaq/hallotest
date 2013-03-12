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
cookie1 = undefined
cookie2 = undefined

cleanup = (done) ->
  keys = [
    "users:test0",
    "users:test1",
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
    "keyversion:test0",
    "keys:test0:1",
    "keyversion:test1",
    "keys:test1:1"]
  rc.del keys, (err, data) ->
    if err
      done err
    else
      done()


login = (username, password, jar, authSig, done, callback) ->
  request.post
    url: baseUri + "/login"
    jar: jar
    json:
      username: username
      password: password
      authSig: authSig
    (err, res, body) ->
      if err
        done err
      else
        cookie = jar.get({ url: baseUri }).map((c) -> c.name + "=" + c.value).join("; ")
        callback res, body, cookie

signup = (username, password, jar, dhPub, dsaPub, authSig, done, callback) ->
  request.post
    url: baseUri + "/users"
    jar: jar
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


describe "surespot chat test", () ->
  keys = undefined
  before (done) ->
    createKeys 2, (err, keyss) ->
      keys = keyss
      cleanup done

  client = undefined
  client1 = undefined
  jsonMessage = {type: "message", to: "test0", toVersion: "1", from: "test1", fromVersion: "1", iv: 1, data: "message data", mimeType: "text/plain"}

  it 'client 1 connect', (done) ->
    jar1 = request.jar()
    signup 'test0', 'test0', jar1, keys[0].ecdh.pem_pub, keys[0].ecdsa.pem_pub, keys[0].sig, done, (res, body, cookie) ->
      client = io.connect baseUri, { 'force new connection': true}, cookie
      cookie1 = cookie
      client.once 'connect', ->
        done()

  it 'client 2 connect', (done) ->
    jar2 = request.jar()
    signup 'test1', 'test1', jar2, keys[1].ecdh.pem_pub, keys[1].ecdsa.pem_pub, keys[1].sig, done, (res, body, cookie) ->
      client1 = io.connect baseUri, { 'force new connection': true}, cookie
      cookie2 = cookie
      client1.once 'connect', ->
        done()

#  it 'should not be able to send a message to a non friend', (done) ->
#    #server will disconnect you!
#    client.once 'disconnect', ->
#      done()
#    client.send JSON.stringify jsonMessage


  it 'should be able to send a message to a friend', (done) ->
    # make them friends
    client1.once 'message', (receivedMessage) ->
      receivedMessage = JSON.parse receivedMessage
      receivedMessage.to.should.equal jsonMessage.to
      receivedMessage.id.should.equal 1
      receivedMessage.from.should.equal jsonMessage.from
      receivedMessage.data.should.equal jsonMessage.data
      receivedMessage.mimeType.should.equal jsonMessage.mimeType
      receivedMessage.iv.should.equal jsonMessage.iv
      done()

    request.post
      jar: jar2
      url: baseUri + "/invite/test0"
      (err, res, body) ->
        if err
          done err
        else
          request.post
            jar: jar1
            url: baseUri + "/invites/test1/accept"
            (err, res, body) ->
              if err
                done err
              else
             #   client = io.connect baseUri, { 'force new connection': true}, cookie1
              #  client.once 'connect', ->
                jsonMessage.from = "test0"
                jsonMessage.to = "test1"
                client.send JSON.stringify(jsonMessage)

  it 'should be able to delete received message', (done) ->
    deleteControlMessage = {}
    deleteControlMessage.type = 'message'
    deleteControlMessage.action = 'delete'
    deleteControlMessage.localid = 1
    deleteControlMessage.data = "test0:test1"
    deleteControlMessage.moredata = 1

    client1.once 'control', (data) ->
      receivedControlMessage = JSON.parse data
      receivedControlMessage.type.should.equal deleteControlMessage.type
      receivedControlMessage.action.should.equal deleteControlMessage.action
      receivedControlMessage.localid.should.equal deleteControlMessage.localid
      receivedControlMessage.data.should.equal deleteControlMessage.data
      receivedControlMessage.moredata.should.equal deleteControlMessage.moredata
      done()

    client1.emit 'control', JSON.stringify(deleteControlMessage)

  it 'deleted received message should be marked as deletedTo', (done) ->
      #get the message to see if it's been marked as deleted
    request.get
      jar: jar1
      url: baseUri + "/messages/test1/after/0"
      (err, res, body) ->
        if err
          done err
        else
          messages = JSON.parse(body)
          message = JSON.parse(messages[0])
          message.deletedTo.should.equal true
          done()


  it 'should be able to delete sent message', (done) ->
    deleteControlMessage = {}
    deleteControlMessage.type = 'message'
    deleteControlMessage.action = 'delete'
    deleteControlMessage.localid = 1
    deleteControlMessage.data = "test0:test1"
    deleteControlMessage.moredata = 1

    client.once 'control', (data) ->
      receivedControlMessage = JSON.parse data
      receivedControlMessage.type.should.equal deleteControlMessage.type
      receivedControlMessage.action.should.equal deleteControlMessage.action
      receivedControlMessage.localid.should.equal deleteControlMessage.localid
      receivedControlMessage.data.should.equal deleteControlMessage.data
      receivedControlMessage.moredata.should.equal deleteControlMessage.moredata
      done()

    client.emit 'control', JSON.stringify(deleteControlMessage)


  it 'deleted message should be marked as deleted', (done) ->
    #get the message to see if it's been marked as deleted
    request.get
      jar: jar1
      url: baseUri + "/messages/test1/after/0"
      (err, res, body) ->
        if err
          done err
        else
          messages = JSON.parse(body)
          message = JSON.parse(messages[0])
          message.data.should.equal 'deleted'
          done()


  after (done) ->
    client.disconnect()
    client1.disconnect()
    done()
#    cleanup done