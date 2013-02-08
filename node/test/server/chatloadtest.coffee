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
baseUri = "https://localhost:" + port
minclient = 0
clients = 1000
sockets = []
#http.globalAgent.maxSockets = 100
#http.request {agent: false}

cleanup = (done) ->

  for i in [minclient..minclient+clients] by 1
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
    #agent: false
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
    #agent: false
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



connect = (i, done) =>
  j = request.jar()
  #console.log 'i: ' + i
  signup 'test' + i, 'test' + i,j, done, (res, body) ->
    cookie = j.get({ url: baseUri }).map((c) -> c.name + "=" + c.value ).join("; ")
    client = io.connect baseUri, { 'force new connection': true}, cookie
    client.once 'connect', ->
      done(null, client)

makef = (i) ->
  return (callback) ->
    connect i, callback




describe "surespot chat test", () ->
  before (done) -> cleanup done

  it "connects #{clients} users", (done) ->
    tasks = []

    for i in [minclient..minclient+clients] by 1
      tasks.push makef i

    async.parallel tasks, (err, sockets) ->
      _.each sockets, (socket) -> socket.disconnect()
      done()


  after (done) -> cleanup done


