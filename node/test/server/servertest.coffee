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
  describe "POST /users with valid form encoded username password", () ->
    it "should respond with 204", (done) ->
      signup "test","test", done, (res, body) ->
        #should get a no content
        res.statusCode.should.equal 201
        done()

    it "should exist", (done) ->
      http.get
        url: baseUri + "/users/test/exists",
        (err,res,body) ->
          if err
            done err
          else
            body.should.equal "true"
            done()


  describe "POST /login form encoded username password", ->
    it "should return 401 with invalid credentials", (done) ->
      login "your", "mama", done, (res, body) ->
        #should get a no content
        res.statusCode.should.equal 401
        done()

    it "should respond with 204 given valid credentials", (done) ->
      login "test","test",done,(res,body) ->
        #should get a no content
        res.statusCode.should.equal 204
        done()

  describe "valid invite exchange", ->
    it "should create another user", (done) ->
      signup "test1","test1", done, (res, body) ->
        #should get a no content
        res.statusCode.should.equal 201
        done()


    it "should be friends", (done) ->
      http.post
        url: baseUri + "/invite/test", (err, res, body) =>
          if err
            done err
          else
            res.statusCode.should.equal 204
            login "test","test",done,(res, body) ->
              http.post
                url: baseUri + "/invites/test1/accept", (err, res, body) ->
                if err
                  done err
                else
                  res.statusCode.should.equal 204
                  done()

  describe "getting the public key of a non friend user", ->
    it "creating a non friend user", (done) ->
      signup "notafriend", "notafriend", done, (res, body) ->
        done()



    #it "should fail", (done) ->
     # http.get
      #  url: baseUri + "/publickey/nonfriend"


  after (done) ->
    keys = ["users:test", "users:test1", "friends:test", "friends:test1", "invites:test", "invited:test1"]
    rc.del keys,(err, res) ->
      done()


