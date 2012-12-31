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
  nodePort = 3000
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
      pass: "c4e5ba6af0cce3ee5b48c3d4964089b6"
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
    app.use express.errorHandler(
      showStack: false
      dumpExceptions: true
    )

  app.listen nodePort
  sio = require("socket.io").listen(app)

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

  #socket io store

  #  var decodedCookie = decodeURIComponent(req.headers.cookie);

  #  req.cookie = connect.utils.parseSignedCookie(req.headers.cookie['connect.sid'], "your mama");

  # save the session store to the data object
  # (as required by the Session constructor)
  #   req.sessionStore = sessionStore;

  # create a session object, passing data as request and our
  # just acquired session data

  #todo namespace room emit broken
  #.of('/blink')

  #see if we're already in some chats and rejoin them

  #todo handle error
  #if (err) next(err);
  #join all the rooms

  #todo get the room from the socket not the message
  #todo check they are part of the room
  #don't trust what the bastard client says about who he is

  #store key in database

  #todo handle error
  #todo send ack

  #keep track of which chats we're joined to

  #todo handle error
  # if (err) next(new Error('[addFriend] sadd failed for username: ' + username + ', friendname' + friendname))

  #todo handle error
  # if (err) next(new Error('[addFriend] sadd failed for username: ' + username + ', friendname' + friendname))

  #  res.send(201);

  #todo get the room from the socket not the message
  #todo check they are part of the room
  #don't trust what the bastard client says about who he is
  #    var user = socket.handshake.session.passport.user;

  #in is reserved in coffeescript

  #add user to user's list of u

  #todo make sure route username matches logged in username

  #return the password in the user object so we can auth

  #join all the rooms

  #send any messages

  #todo handle error

  #
  # app.post('/conversations/:room/keys/:username', ensureAuthenticated, function (req, res, next) {
  # if (req.body.key) {
  # process.nextTick(function () {
  # rc.hset(util.format("conversations:%s:keys", req.params.room), req.params.username, req.body.key, function (err, data) {
  #
  #
  # if (err) next(new Error('Could not set sym key'));
  # //return the password in the user object so we can auth
  #
  #
  # res.send(201);
  #
  # })
  # });
  # }
  # else {
  # next(new Error('No key supplied.'));
  # }
  # })


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
        res.send data
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
        next new Error("[createNewUserAccount] user already exists")
      else
        username = req.body.username
        password = req.body.password
        publickey = req.body.publickey
        userKey = "users:" + username
        bcrypt.genSalt 10, (err, salt) ->
          bcrypt.hash password, salt, (err, password) ->
            rc.hmset userKey, "username", username, "password", password, "publickey", publickey, (err, data) ->
              console.log "set " + userKey + " in db"
              next new Error("[createNewUserAccount] SET failed for user: " + name + "password" + password)  if err

              #return the password in the user object so we can auth
              rc.hgetall userKey, (err, user) ->

                # req.body.password = password;
                #  req.logout();
                req.login user, null, ->
                  req.user = user
                  next()

  getNotifications = (req, res, next) ->
    rc.smembers "invites:#{req.user.username}", (err, users) ->
      next err  if err
      if users.length is 0
        res.send 204
      else
        res.send _.map users, (user) -> {type: 'invite', data: user}


  room = sio.on("connection", (socket) ->
    user = socket.handshake.session.passport.user
    #join notification room
    console.log "user #{user} joining notification room"
    socket.join(user)
    console.log "rejoining spots"
    rc.smembers "users:" + user + ":conversations", (err, data) ->
      unless err
        console.log "no rooms to join"  if data.length is 0
        i = 0

        while i < data.length
          console.log "joining: " + data[i]
          socket.join data[i]
          i++
      else
        console.log "error joining rooms: " + err




    socket.on "create", (data) ->
      console.log "received conversation keys from user: " + user
      message = JSON.parse(data)
      message.user = user
      room = message.room
      rc.hmset "conversations:#{room}:keys", user, message.mykey, message.theirname, message.theirkey, (err, data) ->
        console.log "set keys: " + data
        console.log "received create, joining room: " + room
        socket.join room
        rc.sadd "users:" + user + ":conversations", room, (err, data) ->
          console.log "created conversation: " + room


    socket.on "join", (room) ->
      #user = socket.handshake.session.passport.user
      console.log "received join, joining room: " + room
      socket.join room
      rc.sadd "users:" + user + ":conversations", room, (err, data) ->
        console.log "joined conversation: " + room


    socket.on "message", (data) ->
      #user = socket.handshake.session.passport.user
      message = JSON.parse(data)
      message.user = user
      console.log "sending message from user #{user}"
      room = message.room
      text = message.text
      console.log "sending message " + text + " to room:" + room
      newMessage = JSON.stringify(message)
      rc.rpush "conversations:" + room + ":messages", newMessage
      sio.sockets.in(message.room).emit "message", newMessage

  )

  app.get "/test", (req, res) ->
    res.sendfile path.normalize __dirname + "/../assets/html/test.html"

  app.get "/", (req, res) ->
    res.sendfile path.normalize __dirname + "/../assets/html/layout.html"

  app.get "/friends", ensureAuthenticated, getFriends
  app.get "/publickey/:username", ensureAuthenticated, getPublicKey
  app.get "/notifications", ensureAuthenticated, getNotifications


  app.post "/login", passport.authenticate("local"), (req, res) ->
    console.log "/login post"
    res.send()

  app.post "/users", createNewUserAccount, passport.authenticate("local"), (req, res) ->
    res.send 201


  app.post "/invite/:friendname", ensureAuthenticated, (req, res, next) ->
    friendname = req.params.friendname
    # the caller wants to add himself as a friend
    username = req.user.username
    spot = req.body.spot

    console.log "#{username} inviting #{friendname} to spot #{spot}"
    #todo check both users exist
    userExists friendname, (err, exists) ->
      next err  if err
      unless exists
        console.log "no such user"
        next new Error("[invite friend] no such user")
      else
        #todo check if friendname has ignored username


        #see if they are already friends
        dal.isFriend username, friendname, (err, result) ->
          #if they are, do nothing
          if result is 1 then res.send(204)
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
                  res.send(202)
                else
                  res.send(204)

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
        res.send(201)

  app.get "/conversations/:room/key", ensureAuthenticated, (req, res, next) ->
    rc.hget "conversations:#{req.params.room}:keys", req.user.username, (err, data) ->
      next new Error("Could not get sym key")  if err
      res.send data


  app.get "/conversations", ensureAuthenticated, (req, res, next) ->
    rc.smembers "users:" + req.user.username + ":conversations", (err, data) ->
      next err  if err
      if data.length is 0
        res.send 204
      else
        res.send data


  app.get "/conversations/:room/messages", ensureAuthenticated, (req, res, next) ->
    rc.lrange "conversations:" + req.params.room + ":messages", 0, -1, (err, data) ->
      res.send data  unless err


  app.post "/logout", ensureAuthenticated, (req, res) ->
    req.logout()
    res.send()


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
