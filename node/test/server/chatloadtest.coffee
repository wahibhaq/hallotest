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

port = 443
baseUri = "https://www.surespot.me:" + port
minclient = 1000
clients = 100

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
      callback res, body

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
      callback res, body



createUsers = (i, callback) ->
  j = request.jar()
  #console.log 'i: ' + i
  signup 'test' + i, 'test' + i,j, callback, (res, body) ->
    cookie = j.get({ url: baseUri }).map((c) -> c.name + "=" + c.value ).join("; ")
    callback null, cookie

loginUsers = (i, callback) ->
  j = request.jar()
  #console.log 'i: ' + i
  login 'test' + i, 'test' + i,j, callback, (res, body) ->
    cookie = j.get({ url: baseUri }).map((c) -> c.name + "=" + c.value ).join("; ")
    callback null, cookie

connectChats = (cookie, callback) ->
  client = io.connect baseUri, { 'force new connection': true}, cookie
  client.on 'connect', ->
    callback null, client

makeCreate = (i) ->
  return (callback) ->
    createUsers i, callback


makeLogin = (i) ->
  return (callback) ->
    loginUsers i, callback

makeConnect = (cookie) ->
  return (callback) ->
    connectChats cookie, callback


describe "surespot chat test", () ->
  before (done) -> cleanup done

  tasks = []
  cookies = undefined
  sockets = undefined

  it "create #{clients} users", (done) ->


    #create connect clients tasks
    for i in [minclient..minclient+clients-1] by 1
      tasks.push makeCreate i

    #execute the tasks which creates the cookie jars
    async.parallel tasks, (err, cookies) ->



      #_.each sockets, (socket) -> socket.disconnect()
      done()

  it "login #{clients} users", (done) ->
    tasks = []

    #create connect clients tasks
    for i in [minclient..minclient+clients-1] by 1
      tasks.push makeLogin i

    #execute the tasks which creates the cookie jars
    async.parallel tasks, (err, httpcookies) ->
      cookies = httpcookies
      done()



  it "connect #{clients} chats", (done) ->
    connects = []
    for cookie in cookies
      connects.push makeConnect(cookie)
    async.parallel connects, (err, clients) ->
      sockets = clients
      done()



  after (done) -> cleanup done

