assert = require("assert")
should = require("should")
http = require("request")
redis = require("redis")
util = require("util")
rc = redis.createClient()
port = 443
baseUri = "https://localhost:" + port

login = (username, password, done,  callback) ->
  http.post
    url: baseUri + "/login"
    json:
      username: username
      password: password
  , (err, res, body) ->
    if err
      done err
    else
      callback res, body

signup = (username, password, done,  callback) ->
  http.post
    url: baseUri + "/users"
    json:
      username: username
      password: password
  , (err, res, body) ->
    if err
      done err
    else
      callback res, body


describe "surespot server", () ->
  describe "create user", () ->
    it "should respond with 204", (done) ->
      signup "test","test", done, (res, body) ->
        #should get a no content
        res.statusCode.should.equal 201
        done()

    it "and subsequently exist", (done) ->
      http.get
        url: baseUri + "/users/test/exists",
        (err,res,body) ->
          if err
            done err
          else
            body.should.equal "true"
            done()


  describe "login with invalid credentials", ->
    it "should return 401", (done) ->
      login "your", "mama", done, (res, body) ->
        #should get a no content
        res.statusCode.should.equal 401
        done()

  describe "login with valid credentials", ->
    it "should return 204", (done) ->
      login "test","test",done,(res,body) ->
        #should get a no content
        res.statusCode.should.equal 204
        done()

  describe "valid invite exchange", ->
    it "should create a user", (done) ->
      signup "test1","test1", done, (res, body) ->
        #should get a no content
        res.statusCode.should.equal 201
        done()

    it "who invites another user", (done) ->
      http.post
        url: baseUri + "/invite/test", (err, res, body) =>
          if err
            done err
          else
            res.statusCode.should.equal 204
            done()

    it "who accepts their invite", (done) ->
      login "test","test",done,(res, body) ->
        http.post
          url: baseUri + "/invites/test1/accept", (err, res, body) ->
            if err
              done err
            else
              res.statusCode.should.equal 204
              done()

  describe "inviting non existent user", ->
    it "should return 404", (done) ->
      http.post
        url: baseUri + "/invites/nosuchuser", (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 404
            done()

  describe "getting the public key of a non friend user", ->
    it "should not be allowed", (done) ->
      signup "notafriend", "notafriend", done, (res, body) ->
        http.get
          url: baseUri + "/publickey/test", (err, res, body) ->
            if err
              done err
            else
              res.statusCode.should.equal 403
              done()

  describe "getting other user's last 30 messages", ->
    it "should not be allowed", (done) ->
      http.get
        url: baseUri + "/messages/test", (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()
  describe "getting other user's messages after x", ->
    it "should not be allowed", (done) ->
      http.get
        url: baseUri + "/messages/test/after/0", (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()
  describe "getting other user's messages before x", ->
    it "should not be allowed", (done) ->
      http.get
        url: baseUri + "/messages/test/before/100", (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 403
            done()




  after (done) ->
    keys = ["users:test", "users:test1", "friends:test", "friends:test1", "invites:test", "invited:test","users:notafriend"]
    rc.del keys,(err, res) ->
      done()


