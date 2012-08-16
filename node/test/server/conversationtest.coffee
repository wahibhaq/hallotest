#requirejs = require 'requirejs'
#requirejs.config {
###
  shim:
    "socket.io":
      exports: "io"
###
#paths:
#jquery: "../lib/jquery-1.7.2.min"
# jqm: "../lib/jquery.mobile-1.1.1"
#  "socket.io": "/socket.io/socket.io"

#By default load any module IDs from js/lib#
#baseUrl: "assets/js/app"
#nodeRequire: require}
#/Pass the top-level main.js/index.js require
#/function to requirejs so that node modules
#/are loaded relative to the top-level JS file.


assert = require("assert")
should = require("should")
redis = require("redis")
util = require("util")
rc = redis.createClient()
Browser = require('zombie')
port = 3000
baseUri = "http://localhost:" + port
describe "blink server", ->
  browser = undefined
  $ = undefined
  describe "create user", ->
    username = 'test1'
    password = 'test1'
    networkcontroller = undefined
    networkcontroller2 = undefined
    it "should return 201 if successful", (done) ->
      browser = new Browser({ debug: true })
      browser.visit "http://localhost:3000", (err, browser) ->
        #set the global window to the zombie browser window so jquery can find it
        #lets pull in some client code
        networkcontroller = browser.window.requirejs 'networkcontroller'
        networkcontroller.addUser(
          username,
          password,
          browser.window.localStorage.getItem('publickey'),
          -> done(),
          -> done(new Error('could not add user')))

    it "should respond with 204 given valid credentials", (done) ->
      networkcontroller.login(
        username,
        password,
        -> done(),
        -> done(new Error('could not login')))

    browser2 = undefined
    it "should let me create another user", (done) ->
      # add another user in another browser sesion
      browser2 = new Browser({debug: true})
      browser2.visit "http://localhost:3000", (err, browser) ->
        #set the global window to the zombie browser window so jquery can find it
        #lets pull in some client code
        networkcontroller2 = browser2.window.requirejs 'networkcontroller'
        networkcontroller2.addUser(
          'test2',
          'test2',
          browser2.window.localStorage.getItem('publickey'),
          -> done(),
          -> done(new Error('could not add user')))

    it 'should invite and accept', (done) ->
      #connect 1st dudes socket and listen for friendrequestapproval
      chatcontroller1 = browser.window.requirejs 'chatcontroller'
      chatcontroller2 = browser2.window.requirejs 'chatcontroller'


      chatcontroller1._connect(
        -> chatcontroller2._connect(
          -> networkcontroller.invite(
            'test2',
            ->,
            -> done(new Error('error inviting test2 to be a friend of test1'))),
          (message) -> console.log('received message: ' + message),
          (invitee) ->
            #test2 should have an invite notification from user1
            networkcontroller2.getNotifications(
              (notifications) ->
                notifications.length.should.equal 1
                notifications[0].type.should.equal 'invite'
                notifications[0].data.should.equal invitee.data
                networkcontroller2.respondToInvite(
                  username,'accept',
                  ->,
                  -> done (new Error('could not accept invite')))
              -> done(new Error('could not get notifications'))))
        (message) -> console.log('test1 received message: ' + message),
        (friendname) -> console.log('test1 received invite: ' + friendname),
        (username) ->
          username.should.equal 'test2'
          done())


    after (done) ->
      keys = ["users:test1", "users:test2", "friends:test2", "friends:test1"]
      #, "users:test1user", "users:test2user", "users:test2user:friends", "conversations:test2user_test1user:keys"]
      rc.del keys, (err, res) ->
        res.should.equal keys.length
        done()

###