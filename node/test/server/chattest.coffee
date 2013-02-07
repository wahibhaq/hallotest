http = require("request")
assert = require("assert")
should = require("should")
redis = require("redis")
util = require("util")
fs = require("fs")
io = require 'socket.io-client'
rc = redis.createClient()
port = 443
baseUri = "https://localhost:" + port

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
  http.post
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
  http.post
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

#patch things to send auth cookie in socket.io handshake...thanks to https://gist.github.com/jfromaniello/4087861
#for this to work socket.io-client package.json needs to be changed to use xmlhttprequest version 1.5.0
# then npm update
jar1 = http.jar()
jar2 = http.jar()
j = jar1

originalRequest = require('socket.io-client/node_modules/xmlhttprequest').XMLHttpRequest

` require('socket.io-client/node_modules/xmlhttprequest').XMLHttpRequest = function(){
    originalRequest.apply(this, arguments);
    this.setDisableHeaderCheck(true);
    var stdOpen = this.open;

    /*
    * don't know how to do this in coffeescript, it always returns a value
    */
    this.open = function() {
      stdOpen.apply(this, arguments);
      var header = j.get({ url: baseUri })
      .map(function (c) {
        return c.name + "=" + c.value;
      }).join("; ");
       this.setRequestHeader('cookie', header);
    };
  };`



describe "surespot chat test", () ->
  before (done) -> cleanup done

  client = undefined
  client1 = undefined
  jsonMessage = {to:"test",from:"test1",iv:1,data:"message data",mimeType:"text/plain"}

  it 'client 1 connect', (done) ->
    signup 'test', 'test',jar1, done, (res, body) ->
      j = jar1
      client = io.connect baseUri, { 'force new connection': true}
      client.once 'connect', ->
        done()

  it 'client 2 connect', (done) ->
    signup 'test1', 'test1', jar2, done, (res, body) ->
      j = jar2
      client1 = io.connect baseUri, { 'force new connection': true}
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

    http.post
      jar: jar2
      url: baseUri + "/invite/test", (err, res, body) ->
        if err
          done err
        else
          http.post
            jar: jar1
            url: baseUri + "/invites/test1/accept", (err, res, body) ->
              if err
                done err
              else
                j = jar1
                client = io.connect baseUri, { 'force new connection': true}
                client.once 'connect', ->
                  jsonMessage.from = "test"
                  jsonMessage.to = "test1"
                  client.send JSON.stringify jsonMessage

  after (done) -> cleanup done