requirejs = require 'requirejs'
requirejs.config {
#appDir: '.'
nodeRequire: require
paths:
  {
  'cs': '../assets/js/lib/server/cs'
  }
}

requirejs ['cs!dal', 'underscore'], (DAL, _) ->
  cookie = require("cookie")
  express = require("express")
  passport = require("passport")
  LocalStrategy = require("passport-local").Strategy
  bcrypt = require("bcrypt")
  RedisStore = require("connect-redis")(express)
  path = require 'path'
  util = require("util")
  gcm = require("node-gcm")
  nodePort = 3000
  socketPort = 3000
  sio = undefined
  sessionStore = undefined
  rc = undefined
  pub = undefined
  sub = undefined
  client = undefined
  dal = undefined

  createRedisClient = (port, hostname, password) ->
    if port? and hostname? and password?
      client = require("redis").createClient(port, hostname)
      client.auth password
      client
    else
      require("redis").createClient()


  app = module.exports = express.createServer()

  console.log "process.env.NODE_ENV: " + process.env.NODE_ENV
  console.log "__dirname: #{__dirname}"
  dev = process.env.NODE_ENV is "development"

  app.configure "development", ->
    nodePort = 3000
    socketPort = 3000
    sessionStore = new RedisStore()
    dal = new DAL()
    rc = createRedisClient()
    pub = createRedisClient()
    sub = createRedisClient()
    client = createRedisClient()

  app.configure "amazon-dev-home", ->
    console.log "running on amazon-dev"
    nodePort = 3000
    redisPort = 6379
    socketPort = 3000
    sessionStore = new RedisStore(
      host: "ec2.2fours.com"
      port: redisPort
      pass: "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040"
    )
    rc = createRedisClient(redisPort, "ec2.2fours.com", "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040")
    pub = createRedisClient(redisPort, "ec2.2fours.com", "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040")
    sub = createRedisClient(redisPort, "ec2.2fours.com", "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040")
    client = createRedisClient(redisPort, "ec2.2fours.com", "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040")

  app.configure "amazon-stage", ->
    console.log "running on amazon-stage"
    nodePort = 80
    redisPort = 6379
    socketPort = 443
    redisHost = "127.0.0.1"
    redisAuth = "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040"
    dal = new DAL(redisPort, redisHost, redisAuth)
    sessionStore = new RedisStore(
      host: redisHost
      port: redisPort
      pass: redisAuth
    )
    rc = createRedisClient(redisPort, redisHost, redisAuth)
    pub = createRedisClient(redisPort, redisHost, redisAuth)
    sub = createRedisClient(redisPort, redisHost, redisAuth)
    client = createRedisClient(redisPort, redisHost, redisAuth)

  app.configure "nodester-amazon", ->
    console.log "running on nodester"
    nodePort = process.env["app_port"]
    redisPort = 6379
    dal = new DAL(redisPort, "ec2.2fours.com", "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040")
    sessionStore = new RedisStore(
      host: "ec2.2fours.com"
      port: redisPort
      pass: "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040"
    )
    rc = createRedisClient(redisPort, "ec2.2fours.com", "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040")
    pub = createRedisClient(redisPort, "ec2.2fours.com", "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040")
    sub = createRedisClient(redisPort, "ec2.2fours.com", "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040")
    client = createRedisClient(redisPort, "ec2.2fours.com", "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040")

  app.configure "redistogo-dev", ->
    console.log "running on nodester"
    nodePort = 3000
    sessionStore = new RedisStore(
      host: "chubb.redistogo.com"
      port: 9473
      pass: "c4e5ba6af0cce3ee5b48c3d4964089b6"
    )
    rc = createRedisClient(9473, "chubb.redistogo.com", "c4e5ba6af0cce3ee5b48c3d4964089b6")
    pub = createRedisClient(9473, "chubb.redistogo.com", "c4e5ba6af0cce3ee5b48c3d4964089b6")
    sub = createRedisClient(9473, "chubb.redistogo.com", "c4e5ba6af0cce3ee5b48c3d4964089b6")
    client = createRedisClient(9473, "chubb.redistogo.com", "c4e5ba6af0cce3ee5b48c3d4964089b6")

  app.configure "nodester-stage", ->
    console.log "running on nodester"
    nodePort = process.env["app_port"]
    sessionStore = new RedisStore(
      host: "chubb.redistogo.com"
      port: 9473
      pass: "c4e5ba6-c +
             caf0cce3ee5b48c3d4964089b6"
    )
    rc = createRedisClient(9473, "chubb.redistogo.com", "c4e5ba6af0cce3ee5b48c3d4964089b6")
    pub = createRedisClient(9473, "chubb.redistogo.com", "c4e5ba6af0cce3ee5b48c3d4964089b6")
    sub = createRedisClient(9473, "chubb.redistogo.com", "c4e5ba6af0cce3ee5b48c3d4964089b6")
    client = createRedisClient(9473, "chubb.redistogo.com", "c4e5ba6af0cce3ee5b48c3d4964089b6")

  app.configure "heroku-stage", ->
    console.log "running on heroku"
    nodePort = process.env.PORT

  app.configure ->
    app.use express.logger()
    app.use express["static"](__dirname + "/../assets")
    app.use express.cookieParser()
    app.use express.bodyParser()
    app.use express.session(
      secret: "your mama"
      store: sessionStore
    )
    app.use passport.initialize()
    app.use passport.session()
    app.use app.router
    app.use express.errorHandler({
    showMessage: true,
    showStack: false,
    dumpExceptions: false
    })

  app.listen nodePort
  if nodePort == socketPort
    sio = require("socket.io").listen(app)
  else
    sio = require("socket.io").listen(socketPort)

  app.configure "heroku-stage", ->
    sio.configure ->
      sio.set "transports", ["xhr-polling"]
      sio.set "polling duration", 10


  sioRedisStore = require("socket.io/lib/stores/redis")
  sio.set "store", new sioRedisStore(
    redisPub: pub
    redisSub: sub
    redisClient: client
  )

  sio.set "authorization", (req, accept) ->
    console.log 'socket.io auth'
    if req.headers.cookie
      parsedCookie = cookie.parse(req.headers.cookie)
      req.sessionID = parsedCookie["connect.sid"]
      sessionStore.get req.sessionID, (err, session) ->
        if err or not session
          accept "Error", false
        else
          req.session = session
          if req.session.passport.user
            accept null, true
          else
            accept "Error", false

    else
      accept "No cookie transmitted.", false


  ensureAuthenticated = (req, res, next) ->
    console.log "ensureAuth"
    if req.isAuthenticated()
      console.log "authorized"
      next()
    else
      console.log "401"
      res.send 401

  getRoomName = (from, to) ->
    if from < to then from + ":" + to else to + ":" + from

  getFriends = (req, res, next) ->
    username = req.user.username
    dal.getFriends username, (err, data) ->
      next err  if err
      res.send data

  getPublicKey = (req, res, next) ->
    if req.params.username
      username = req.params.username
      rc.hget "users:" + username, "publickey", (err, data) ->
        next err  if err
        if data?
          res.send data
        else
          res.send 404
    else
      next new Error("No username supplied.")

  userExists = (username, fn) ->
    userKey = "users:" + username
    rc.hlen userKey, (err, hlen) ->
      return fn(new Error("[userExists] failed for user: " + username))  if err
      fn null, hlen > 0

  createNewUserAccount = (req, res, next) ->
    console.log "createNewUserAccount"

    #var newUser = {name:name, email:email };
    userExists req.body.username, (err, exists) ->
      next err  if err
      if exists
        console.log "user already exists"
        res.send 409
      else
        username = req.body.username
        password = req.body.password
        publickey = req.body.publickey
        gcmId = req.body.gcmId
        console.log "gcmID: " + gcmId

        userKey = "users:" + username
        bcrypt.genSalt 10, (err, salt) ->
          next err if err
          bcrypt.hash password, salt, (err, password) ->
            next err if err
            rc.hmset userKey, "username", username, "password", password, "publickey", publickey, "gcmId", gcmId, (err, data) ->
              console.log "set " + userKey + " in db"
              next new Error("[createNewUserAccount] SET failed for user: " + username)  if err

              #return the password in the user object so we can auth
              #todo build manually instead of reading back from redis
              rc.hgetall userKey, (err, user) ->
                next err if err
                # req.body.password = password;
                #  req.logout();
                #auth login
                req.login user, null, ->
                  req.user = user
                  next()

  getNotifications = (req, res, next) ->
    rc.smembers "invites:#{req.user.username}", (err, users) ->
      next err  if err
      res.send _.map users, (user) -> {type: 'invite', data: user}


  room = sio.on("connection", (socket) ->
    user = socket.handshake.session.passport.user

    #join user's room
    console.log "user #{user} joining socket.io room"
    socket.join(user)

    socket.on "message", (data) ->
      user = socket.handshake.session.passport.user

      #todo check user == message.from
      #todo check from and to are friends
      message = JSON.parse(data)

      # message.user = user
      console.log "sending message from user #{user}"

      to = message.to
      from = message.from
      text = message.text
      room = getRoomName(from, to)

      #INCR per chat message id
      rc.incr room + ":id", (err, id) ->
        if err?
          console.log ("ERROR: " + err)
          return


        message.id = id

        console.log "sending message, id:  " + id + ", text: " + text + " to user:" + to
        newMessage = JSON.stringify(message)

        #store messages in sorted sets
        rc.zadd "messages:" + room, id, newMessage, ->
          sio.sockets.to(to).emit "message", newMessage
          sio.sockets.to(from).emit "message", newMessage

          #send gcm message
          userKey = "users:" + to
          rc.hget userKey, "gcmId", (err, gcm_id) ->
            if err?
              console.log ("ERROR: " + err)
              return

            if gcm_id? && gcm_id.length > 0
              console.log "sending gcm message"
              gcmmessage = new gcm.Message()
              sender = new gcm.Sender("AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ")
              gcmmessage.addData("type", "message")
              gcmmessage.addData("to", message.to)
              gcmmessage.addData("sentfrom", message.from)
              gcmmessage.addData("text", message.text)
              gcmmessage.delayWhileIdle = true
              gcmmessage.timeToLive = 3
              gcmmessage.collapseKey = "message"
              regIds = [gcm_id]

              sender.send gcmmessage, regIds, 4, (result) ->
                console.log(result)
            else
              console.log "no gcm id for #{to}"


  )

  #get last x messages
  app.get "/messages/:remoteuser", ensureAuthenticated, (req, res, next) ->
    #todo make sure they are friends
    #return last x messages
    rc.zrange "messages:" + getRoomName(req.user.username, req.params.remoteuser), -50, -1, (err, data) ->
      next err if err
      res.send data


  #get remote messages since id
  app.get "/messages/:remoteuser/:id", ensureAuthenticated, (req, res, next) ->
    #todo make sure they are friends
    #return messages since id
    rc.zrangebyscore "messages:" + getRoomName(req.user.username, req.params.remoteuser), "("+req.params.id, "+inf", (err, data) ->
      next err if err
      res.send data



  app.get "/test", (req, res) ->
    res.sendfile path.normalize __dirname + "/../assets/html/test.html"

  app.get "/", (req, res) ->
    res.sendfile path.normalize __dirname + "/../assets/html/layout.html"

  app.get "/friends", ensureAuthenticated, getFriends
  app.get "/publickey/:username", ensureAuthenticated, getPublicKey
  app.get "/notifications", ensureAuthenticated, getNotifications
  app.get "/users/:username/exists", (req, res) ->
    userExists req.params.username, (err, exists) ->
      next err  if err
      res.send exists


  app.post "/login", passport.authenticate("local"), (req, res) ->
    console.log "/login post"
    res.send 204

  app.post "/users", createNewUserAccount, passport.authenticate("local"), (req, res) ->
    res.send 201

  app.post "/registergcm", ensureAuthenticated, (req, res) ->
    gcmId = req.body.gcmId
    userKey = "users:" + req.user.username
    rc.hset userKey, "gcmId", gcmId, (err) ->
      next err if err
      res.send 204

  app.post "/invite/:friendname", ensureAuthenticated, (req, res, next) ->
    friendname = req.params.friendname
    # the caller wants to add himself as a friend
    username = req.user.username
    spot = req.body.spot

    console.log "#{username} inviting #{friendname} to be friends"
    #todo check both users exist
    userExists friendname, (err, exists) ->
      next err  if err
      unless exists
        console.log "no such user"
        res.send 404
      else
        #todo check if friendname has ignored username


        #see if they are already friends
        dal.isFriend username, friendname, (err, result) ->
          #if they are, do nothing
          if result is 1 then res.send 409
          else
            #todo use transaction
            #add to the user's set of people he's invited
            rc.sadd "invited:#{username}", friendname, (err, invitedCount) ->
              next new Error("Could not set invited") if err

              rc.sadd "invites:#{friendname}", username, (err, invitesCount) ->
                next new Error("Could not set invites") if err

                #send to room
                #todo push notification
                if invitesCount > 0
                  sio.sockets.in(friendname).emit "notification", {type: 'invite', data: username}
                  #send gcm message
                  userKey = "users:" + friendname
                  rc.hget userKey, "gcmId", (err, gcmId) ->
                    if err?
                      console.log ("ERROR: " + err)
                      next new Error("No gcm key.")

                    if gcmId and gcmId.length > 0
                      console.log "sending gcm message"
                      gcmmessage = new gcm.Message()
                      sender = new gcm.Sender("AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ")
                      gcmmessage.addData("type", "invite")
                      gcmmessage.addData("user", username)
                      gcmmessage.delayWhileIdle = true
                      gcmmessage.timeToLive = 3
                      gcmmessage.collapseKey = "invite"
                      regIds = [gcmId]

                      sender.send gcmmessage, regIds, 4, (result) ->
                        console.log(result)
                        res.send 204
                    else
                      console.log "gcmId not set for #{friendname}"
                else
                  res.send 403


  app.post '/invites/:friendname/:action', ensureAuthenticated, (req, res, next) ->
    console.log 'POST /invites'
    username = req.user.username
    friendname = req.params.friendname
    accept = req.params.action is 'accept'
    #todo use transaction?
    rc.srem "invited:#{friendname}", username, (err, data) ->
      next new Error("[friend] srem failed for invited:#{friendname}: " + username) if err
      rc.srem "invites:#{username}", friendname, (err, data) ->
        #send to room
        #TOdo push\
        if accept
          rc.sadd "friends:#{username}", friendname, (err, data) ->
            next new Error("[friend] sadd failed for username: " + username + ", friendname" + friendname) if err
            rc.sadd "friends:#{friendname}", username, (err, data) ->
              next new Error("[friend] sadd failed for username: " + friendname + ", friendname" + username) if err
              sio.sockets.to(friendname).emit "friend", username

        else
          rc.sadd "ignores:#{username}", friendname, (err, data) ->
            next new Error("[friend] sadd failed for username: " + username + ", friendname" + friendname) if err
        res.send 204


  app.post "/logout", ensureAuthenticated, (req, res) ->
    req.logout()
    res.send 204


  process.on "uncaughtException", uncaught = (err) ->
    console.log "Uncaught Exception: ", err

  passport.use new LocalStrategy((username, password, done) ->
    userKey = "users:" + username
    console.log "looking for: " + userKey
    console.log "password: " + password
    rc.hgetall userKey, (err, user) ->
      return done(err)  if err
      unless user
        return done(null, false,
          message: "Unknown user"
        )
      console.log "user.password: " + user.password
      bcrypt.compare password, user.password, (err, res) ->
        return fn(new Error("[bcrypt.compare] failed with error: " + err))  if err
        console.log res
        return done(null, user)  if res is true
        done null, false,
          message: "Invalid password"


  )

  passport.serializeUser (user, done) ->
    console.log "serializeUser, username: " + user.username
    done null, user.username

  passport.deserializeUser (username, done) ->
    console.log "deserializeUser, user:" + username
    rc.hgetall "users:" + username, (err, user) ->
      done err, user
