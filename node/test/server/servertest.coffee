assert = require("assert")
should = require("should")
http = require("request")
redis = require("redis")
util = require("util")
rc = redis.createClient()
port = 443
baseUri = "https://localhost:" + port
describe "surespot server", () ->
  describe "POST /users with valid form encoded username password", () ->
    it "should respond with 204", (done) ->
      
      #before(checkServerIsRunning)
      http.post
        url: baseUri + "/users"
        json:
          username: "test"
          password: "test"
      , (err, res, body) ->
          if err
            done err
          else
          
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
      http.post
        url: baseUri + "/login"
        json:
          username: "your"
          password: "mama"
      , (err, res, body) ->
        if err
          done err
        else
          
          #should get a no content
          res.statusCode.should.equal 401
          done()


    it "should respond with 204 given valid credentials", (done) ->
      http.post
        url: baseUri + "/login"
        json:
          username: "test"
          password: "test"
      , (err, res, body) ->
        if err
          done err
        else
          
          #should get a no content
          res.statusCode.should.equal 204
          done()




  describe "valid invite exchange", ->
    it "should create another user", (done) ->
      http.post
        url: baseUri + "/users"
        json:
          username: "test1"
          password: "test1"
      , (err, res, body) ->
        if err
          done err
        else

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
            http.post
              url: baseUri + "/login"
              json:
                username: "test"
                password: "test"
            , (err, res, body) ->
              if err
                done err
              else
                http.post
                  url: baseUri + "/invites/test1/accept", (err, res, body) ->
                  if err
                    done err
                  else
                    res.statusCode.should.equal 204
                    done()

  after (done) ->
    keys = ["users:test", "users:test1", "friends:test", "friends:test1", "invites:test", "invited:test1"]
    rc.del keys,(err, res) ->
      done()