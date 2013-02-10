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

rc = redis.createClient()

baseUri = "https://localhost"
minclient = 0
clients = 10
jars = []

http.globalAgent.maxSockets = 1000

cleanup = (done) ->
  for i in [minclient..minclient+clients-1] by 1
    num = i
    keys = [
      "users:test#{num}",
      "friends:test#{num}",
      "invites:test#{num}",
      "invited:test#{num}",
      "test:test#{num}:id",
      "messages:test:test#{num}",
      "conversations:test#{num}"]
    rc.del keys, (err, blah) ->
  done()


login = (username, password, jar, done, callback) ->
  request.post
    agent: false
    maxSockets: 1000
    url: baseUri + "/login"
    jar: jar
    json:
      username: username
      password: password
  , (err, res, body) ->
    if err
      done err
    else
      cookie = jar.get({ url: baseUri }).map((c) -> c.name + "=" + c.value).join("; ")
      callback res, body, cookie

signup = (username, password, jar, done, callback) ->
  request.post
    agent: false
    maxSockets: 1000
    url: baseUri + "/users"
    jar: jar
    json:
      username: username
      password: password
  , (err, res, body) ->
    if err
      done err
    else
      cookie = jar.get({ url: baseUri }).map((c) -> c.name + "=" + c.value).join("; ")
      callback res, body, cookie


createUsers = (i, callback) =>
  j = request.jar()
  jars[i] = j
  #console.log 'i: ' + i
  signup 'test' + i, 'test' + i, j, callback, (res, body, cookie) =>
    callback null, cookie

makeCreate = (i) ->
  return (callback) ->
    createUsers i, callback


loginUsers = (i, callback) ->
  j = request.jar()
  #console.log 'i: ' + i
  login 'test' + i, 'test' + i, j, callback, (res, body, cookie) ->
    #cookie = j.get({ url: baseUri }).map((c) -> c.name + "=" + c.value ).join("; ")
    callback null, cookie

makeLogin = (i) ->
  return (callback) ->
    loginUsers i, callback

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
    jar: jars[i]
    url: baseUri + "/invite/test#{i+1}", (err, res, body) ->
      if err
        callback err
      else
        request.post
          jar: jars[i + 1]
          url: baseUri + "/invites/test#{i}/accept", (err, res, body) ->
          if err
            callback err
          else
            callback null


makeFriendUser = (i) ->
  return (callback) ->
    friendUser i, callback


describe "surespot chat test", () ->
  before (done) -> cleanup done

  tasks = []
  cookies = undefined
  sockets = undefined

  it "create #{clients} users", (done) ->


    #create connect clients tasks
    for i in [minclient..minclient + clients - 1] by 1
      tasks.push makeCreate i

    #execute the tasks which creates the cookie jars
    async.parallel tasks, (err, httpcookies) ->
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
    async.parallel tasks, (err, callback) -> done()

  it "connect #{clients} chats", (done) ->
    connects = []
    for cookie in cookies
      connects.push makeConnect(cookie)
    async.parallel connects, (err, clients) ->
      sockets = clients
      done()


  it "send and receive a message", (done) ->
    sends = []
    i = 0
    for socket in sockets
      sends.push makeSend(socket, i++)

    async.parallel sends, (err, results) ->
      _.every results, (result) -> result.should.be.true
      done()


  #after (done) -> cleanup done

