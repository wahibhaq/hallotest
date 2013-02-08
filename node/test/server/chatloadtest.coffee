request = require("request")
http = require 'http'
assert = require("assert")
should = require("should")
redis = require("redis")
util = require("util")
fs = require("fs")
io = require 'socket.io-client'
async = require 'async'
rc = redis.createClient()
port = 443
baseUri = "https://localhost:" + port
j=undefined
minclient = 0
clients = 5
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

#patch things to send auth cookie in socket.io handshake...thanks to https://gist.github.com/jfromaniello/4087861
#for this to work socket.io-client package.json needs to be changed to use xmlhttprequest version 1.5.0
# then npm update



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


connectAll = (num, done, finished) ->
  curr = minclient
  connect = (i) ->
    j = request.jar()
    signup 'test' + i, 'test' + i,j, done, (res, body) ->
      client = io.connect baseUri, { 'force new connection': true}
      client.once 'connect', ->
        if i < num
          connect ++curr
        else
          finished()
  connect curr

describe "surespot chat test", () ->
  before (done) -> cleanup done

  it 'connects 10 users', (done) ->
    connectAll clients, done, ->
      done()




  after (done) -> cleanup done


