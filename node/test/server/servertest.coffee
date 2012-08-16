assert = require("assert")
should = require("should")
http = require("request")
redis = require("redis")
util = require("util")
rc = redis.createClient()
port = 3000
baseUri = "http://localhost:" + port
describe "blink server", ->
  describe "POST /users with valid form encoded username password", ->
    it "should respond with 204", (done) ->
      
      #before(checkServerIsRunning)
      http.post
        url: baseUri + "/users"
        json:
          username: "test"
          password: "test"
      , (err, res, body) ->
          if errdone err
          else
          
            #should get a no content
            res.statusCode.should.equal 201
            done()


    it "should create a user with username password hashes in the database", (done) ->
      
      #hash should have username and password
      rc.hexists "users:test", "username", (err, res) ->
        res.should.equal 1
        rc.hexists "users:test", "password", (err, res) ->
          res.should.equal 1
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



  describe "POST /users/:username:friends json username in body", ->
    it "should add test1user to test2user's friends", (done) ->
      http.post
        url: baseUri + "/users"
        json:
          username: "test1user"
          password: "test1user"
      , (err, res, body) ->
        if err
          done err
        else
          http.post
            url: baseUri + "/users"
            json:
              username: "test2user"
              password: "test2user"
          , (err, res, body) ->
            if err
              done err
            else
              http.post
                url: baseUri + "/users/test2user/friends"
                json:
                  username: "test1user"
              , (err, res, body) ->
                if err
                  done err
                else
                  
                  #should get a no content
                  res.statusCode.should.equal 201
                  done()




    describe "conversations", ->
      it "should set conversation sym key", ->
        http.post
          url: util.format("%s/conversations/%s/keys/%s", baseUri, "test2user_test1user", "test1user")
          json:
            key: "this is not a real key"
        , (err, res, body) ->
          if err
            done err
          else
            
            #should get a no content
            res.statusCode.should.equal 201
            done()


      it "should get said key", ->
        http.get util.format("%s/conversations/%s/keys/%s", baseUri, "test2user_test1user", "test1user"), (err, res, body) ->
          if err
            done err
          else
            res.statusCode.should.equal 200
            body.should.equal "this is not a real key"
            done()



    after (done) ->
      keys = ["users:test", "users:test1user", "users:test2user", "users:test2user:friends", "conversations:test2user_test1user:keys"]
      
      # rc.del(keys
      #        , function (err, res) {
      #          res.should.equal(keys.length);
      done()




#})
