request = require("request")
assert = require("assert")
should = require("should")
redis = require("redis")
util = require("util")
fs = require("fs")
io = require 'socket.io-client'
rc = redis.createClient()
port = 443
baseUri = "https://localhost:" + port
jar1 = undefined
jar2 = undefined
cookie1 = undefined
cookie2 = undefined

cleanup = (done) ->
  keys = [
    "users:test",
    "users:test1",
    "friends:test",
    "friends:test1",
    "invites:test",
    "invited:test",
    "invites:test1",
    "invited:test1",
    "test:test1:id",
    "messages:test:test1",
    "conversations:test1",
    "conversations:test"]
  rc.del keys, (err, data) ->
    if err
      done err
    else
      done()



login = (username, password, jar, done, callback) ->
  request.post
    url: baseUri + "/login"
    jar: jar
    json:
      username: username
      password: password
  , (err, res, body) ->
    if err
      done err
    else
      cookie = jar.get({ url: baseUri }).map((c) -> c.name + "=" + c.value ).join("; ")
      callback res, body, cookie

signup = (username, password, jar, done, callback) ->
  request.post
    url: baseUri + "/users"
    jar: jar
    json:
      username: username
      password: password
  , (err, res, body) ->
    if err
      done err
    else
      cookie = jar.get({ url: baseUri }).map((c) -> c.name + "=" + c.value ).join("; ")
      callback res, body, cookie

describe "surespot chat test", () ->
  before (done) -> cleanup done

  client = undefined
  client1 = undefined
  jsonMessage = {to:"test",from:"test1",iv:1,data:"message data",mimeType:"text/plain"}

  it 'client 1 connect', (done) ->
    jar1 = request.jar()
    signup 'test', 'test', jar1 , done, (res, body, cookie) ->
      client = io.connect baseUri, { 'force new connection': true}, cookie
      cookie1 = cookie
      client.once 'connect', ->
        done()

  it 'client 2 connect', (done) ->
    jar2 = request.jar()
    signup 'test1', 'test1', jar2, done, (res, body, cookie) ->
      client1 = io.connect baseUri, { 'force new connection': true}, cookie
      cookie2 = cookie
      client1.once 'connect', ->
        done()

  it 'should not be able to send a message to a non friend', (done) ->
    #server will disconnect you!
    client.once 'disconnect', ->
      done()
    client.send JSON.stringify jsonMessage


  it 'should be able to send a message to a friend', (done) ->
    # make them friends
    client1.once 'message', (receivedMessage) ->
      receivedMessage = JSON.parse receivedMessage
      receivedMessage.to.should.equal jsonMessage.to
      receivedMessage.id.should.equal 1
      receivedMessage.from.should.equal jsonMessage.from
      receivedMessage.data.should.equal jsonMessage.data
      receivedMessage.mimeType.should.equal jsonMessage.mimeType
      done()

    request.post
      jar: jar2
      url: baseUri + "/invite/test", (err, res, body) ->
        if err
          done err
        else
          request.post
            jar: jar1
            url: baseUri + "/invites/test1/accept", (err, res, body) ->
              if err
                done err
              else
                client = io.connect baseUri, { 'force new connection': true}, cookie1
                client.once 'connect', ->
                  jsonMessage.from = "test"
                  jsonMessage.to = "test1"
                  client.send JSON.stringify jsonMessage

  after (done) -> cleanup done