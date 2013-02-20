request = require("request")
http = require 'http'
assert = require("assert")
should = require("should")
redis = require("redis")
util = require("util")
fs = require("fs")
io = require 'socket.io-client'
async = require 'async'
_ = require 'underscore'
dcrypt = require 'dcrypt'
crypto = require 'crypto'

rc = redis.createClient()

baseUri = "https://localhost"
minclient = 1000
clients = 2000
maxsockets = 100
jars = []

http.globalAgent.maxSockets = maxsockets

cleanup = (done) ->
  keys1 = []
  keys2 = []
  keys3 = []
  keys4 = []
  keys5 = []
  keys6 = []
  keys7 = []
  for i in [minclient..minclient + clients - 1] by 1
    keys1.push "users:test#{i}"
    keys2.push "friends:test#{i}"
    keys3.push "invites:test#{i}"
    keys4.push "invited:test#{i}"
    keys5.push "test#{i}:test#{i + 1}:id"
    keys6.push "messages:test#{i}:test#{i + 1}"
    keys7.push "conversations:test#{i}"
  rc.del keys1, (err, blah) ->
    return done err if err?
    rc.del keys2, (err, blah) ->
      return done err if err?
      rc.del keys3, (err, blah) ->
        return done err if err?
        rc.del keys4, (err, blah) ->
          return done err if err?
          rc.del keys5, (err, blah) ->
            return done err if err?
            rc.del keys6, (err, blah) ->
              return done err if err?
              rc.del keys7, (err, blah) ->
                done()


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

createKeys = (minclient, maxclient, done) ->
  keys = []
  for i in [minclient..maxclient] by 1
    keys.push makeKeys(i)

  async.parallel keys, (err, results) ->
    if err?
      done err
    else
      done null, results


login = (username, password, jar, authSig, done, callback) ->
  request.post
    agent: false
    maxSockets: maxsockets
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
        res.statusCode.should.equal 204
        cookie = jar.get({ url: baseUri }).map((c) -> c.name + "=" + c.value).join("; ")
        callback res, body, cookie

signup = (username, password, jar, dhPub, dsaPub, authSig, done, callback) ->
  request.post
    agent: false
    maxSockets: maxsockets
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
        res.statusCode.should.equal 201
        cookie = jar.get({ url: baseUri }).map((c) -> c.name + "=" + c.value).join("; ")
        callback res, body, cookie


createUsers = (i, key, callback) ->
  j = request.jar()
  jars[i - minclient] = j
  #console.log 'i: ' + i
  signup 'test' + i, 'test' + i, j, key.ecdh.pem_pub, key.ecdsa.pem_pub, key.sig, callback, (res, body, cookie) ->
    callback null, cookie

makeCreate = (i, key) ->
  return (callback) ->
    createUsers(i, key, callback)


loginUsers = (i, key, callback) ->
  j = request.jar()
  #console.log 'i: ' + i
  login 'test' + i, 'test' + i, j, key.sig, callback, (res, body, cookie) ->
    #cookie = j.get({ url: baseUri }).map((c) -> c.name + "=" + c.value ).join("; ")
    callback null, cookie

makeLogin = (i, key) ->
  return (callback) ->
    loginUsers i, key, callback

makeConnect = (cookie) ->
  return (callback) ->
    connectChats cookie, callback


connectChats = (cookie, callback) ->
  client = io.connect baseUri, { 'force new connection': true}, cookie
  client.on 'connect', ->
    callback null, client

send = (socket, i, callback) ->
  if i % 2 is 0
    jsonMessage = {to: "test" + (i + 1), from: "test#{i}", iv: i, data: "message data", mimeType: "text/plain"}
    socket.send JSON.stringify(jsonMessage)
    callback null, true
  else
    socket.once "message", (message) ->
      receivedMessage = JSON.parse message
      callback null, receivedMessage.data is 'message data'


makeSend = (socket, i) ->
  return (callback) ->
    send socket, i, callback


friendUser = (i, callback) ->
  request.post
    agent: false
    maxSockets: maxsockets
    jar: jars[i - minclient]
    url: baseUri + "/invite/test#{i + 1}"
    (err, res, body) ->
      if err
        callback err
      else
        res.statusCode.should.equal 204
        request.post
          agent: false
          maxSockets: maxsockets
          jar: jars[i - minclient + 1]
          url: baseUri + "/invites/test#{i}/accept"
          (err, res, body) ->
            if err
              callback err
            else
              res.statusCode.should.equal 204
              callback null


makeFriendUser = (i) ->
  return (callback) ->
    friendUser i, callback


describe "surespot chat test", () ->
  before (done) -> cleanup done

  keys = undefined
  tasks = []
  cookies = undefined
  sockets = undefined

  it "create #{clients} users", (done) ->
    createKeys minclient, minclient + clients - 1 , (err, keyss) ->
      if err?
        done err
      else
        keys = keyss

        #create connect clients tasks
        for i in [minclient..minclient + clients - 1] by 1
          tasks.push makeCreate i, keys[i - minclient]

        #execute the tasks which creates the cookie jars
        async.series tasks, (err, httpcookies) ->
          if err?
            done err
          else
            cookies = httpcookies
            done()

  #  it "login #{clients} users", (done) ->
  #    tasks = []
  #
  #    #create connect clients tasks
  #    for i in [minclient..minclient+clients-1] by 1
  #      tasks.push makeLogin i
  #
  #    #execute the tasks which creates the cookie jars
  #    async.parallel tasks, (err, httpcookies) ->
  #      cookies = httpcookies
  #      done()


  it 'friend users', (done) ->
    tasks = []
    for i in [minclient..minclient + clients - 1] by 2
      tasks.push makeFriendUser i
    async.series tasks, (err, callback) -> done()

  it "connect #{clients} chats", (done) ->
    connects = []
    for cookie in cookies
      connects.push makeConnect(cookie)
    async.series connects, (err, clients) ->
      if err?
        done err
      else
        sockets = clients
        done()


  it "send and receive a message", (done) ->
    sends = []
    i = 0
    for socket in sockets
      sends.push makeSend(socket, minclient + i++)

    async.series sends, (err, results) ->
      if err?
        done err
      else
        _.every results, (result) -> result.should.be.true
        done()

  after (done) -> cleanup done

