requirejs = require 'requirejs'
requirejs.config {
#appDir: '.'
nodeRequire: require
paths:
  {
  'cs': '../assets/js/lib/server/cs'
  }
}

requirejs ['cs!dal', 'underscore', 'winston'], (DAL, _, winston) ->
  cookie = require("cookie")
  express = require("express")
  passport = require("passport")
  LocalStrategy = require("passport-local").Strategy
  bcrypt = require("bcrypt")
  RedisStore = require("connect-redis")(express)
  path = require 'path'
  util = require("util")
  gcm = require("node-gcm")
  fs = require("fs")
  mkdirp = require("mkdirp")
  logger = require("winston")
  logger.remove winston.transports.Console
  logger.add winston.transports.Console, {'colorize':true}
  logger.add winston.transports.File, { filename: 'server.log', maxsize: 1024576, maxFiles: 20, json: false }


  expressWinston = require "express-winston"

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

  logger.debug "process.env.NODE_ENV: " + process.env.NODE_ENV
  logger.debug "__dirname: #{__dirname}"
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
    logger.debug "running on amazon-dev"
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
    logger.debug "running on amazon-stage"
    nodePort = 8080
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
    logger.debug "running on nodester"
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
    logger.debug "running on nodester"
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
    logger.debug "running on nodester"
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
    logger.debug "running on heroku"
    nodePort = process.env.PORT

  app.configure ->
    app.use express["static"](__dirname + "/../assets")
    app.use express.cookieParser()
    app.use express.bodyParser()
    app.use express.session(
      secret: "your mama"
      store: sessionStore
    )
    app.use passport.initialize()
    app.use passport.session()
    app.use expressWinston.logger({
      transports: [logger]
    })
    app.use app.router
    app.use expressWinston.errorLogger({
      transports: [logger]
    })


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

  sio.configure "amazon-stage", ->
    sio.set "log level", 3

  #winston up some socket.io
  sio.set "logger", {debug: logger.debug, info: logger.info, warn: logger.warn, error: logger.error }

  sioRedisStore = require("socket.io/lib/stores/redis")
  sio.set "store", new sioRedisStore(
    redisPub: pub
    redisSub: sub
    redisClient: client
  )

  sio.set "authorization", (req, accept) ->
    logger.debug 'socket.io auth'
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
    logger.debug "ensureAuth"
    if req.isAuthenticated()
      logger.debug "authorized"
      next()
    else
      logger.debug "401"
      res.send 401

  setNoCache = (req,res,next) ->
    res.setHeader "Cache-Control", "no-cache"
    next()

  setCache = (seconds) -> (req,res,next) ->
    res.setHeader "Cache-Control", "public, max-age=#{oneYear}"
    next()

  getRoomName = (from, to) ->
    if from < to then from + ":" + to else to + ":" + from

  getOtherUser = (room, user) ->
    users = room.split ":"
    if user == users[0] then return users[1] else return users[0]

  getPublicKey = (req, res, next) ->
    if req.params.username
      username = req.params.username
      rc.hget "users:" + username, "publickey", (err, data) ->
        return next err if err
        if data?
          res.setHeader "Cache-Control", "public, max-age=#{oneYear}"
          res.send data
        else
          res.send 404
    else
      return next new Error("No username supplied.")

  getMessages = (room, count, fn) ->
    #return last x messages
    rc.zrange "messages:" + room, -count, -1, (err, data) ->
      return fn err if err?
      fn null, data

  getMessagesAfterId = (room, id, fn) ->
    rc.zrangebyscore "messages:" + room, "("+id, "+inf", (err, data) ->
      return fn err if err?
      fn null, data

  getMessagesBeforeId = (room, id, fn) ->
    rc.zrangebyscore "messages:" + room,  id-30, "("+id , (err, data) ->
      return fn err if err?
      fn null, data


  userExists = (username, fn) ->
    userKey = "users:" + username
    rc.hlen userKey, (err, hlen) ->
      return fn(new Error("[userExists] failed for user: " + username))  if err
      fn null, hlen > 0

  createNewUserAccount = (req, res, next) ->
    logger.debug "createNewUserAccount"

    #var newUser = {name:name, email:email };
    userExists req.body.username, (err, exists) ->
      return next err if err?
      if exists
        logger.debug "user already exists"
        res.send 409
      else
        username = req.body.username
        password = req.body.password
        publickey = req.body.publickey
        gcmId = req.body.gcmId
        logger.debug "gcmID: " + gcmId

        userKey = "users:" + username
        bcrypt.genSalt 10, (err, salt) ->
          return next err if err?
          bcrypt.hash password, salt, (err, password) ->
            return next err if err?
            rc.hmset userKey, "username", username, "password", password, "publickey", publickey, "gcmId", gcmId, (err, data) ->
              logger.debug "set " + userKey + " in db"
              return next new Error("[createNewUserAccount] SET failed for user: " + username) if err?

              #return the password in the user object so we can auth
              #todo build manually instead of reading back from redis
              rc.hgetall userKey, (err, user) ->
                return next err if err?
                # req.body.password = password;
                #  req.logout();
                #auth login
                req.login user, null, ->
                  req.user = user
                  next()

  checkForDuplicateMessage = (resendId, room, message, callback) ->
    if (resendId?)
      if (resendId > 0)
        logger.debug "searching room: #{room} from id: #{resendId} for duplicate messages"
        #check messages client doesn't have for dupes
        getMessagesAfterId room, resendId, (err,data) ->
          return callback err if err
          found = _.find data, (checkMessageJSON) ->
            checkMessage = JSON.parse(checkMessageJSON)
            if checkMessage.id? and message.id?
              logger.debug "comparing ids"
              checkMessage.id == message.id
            else
              logger.debug "comparing ivs"
              checkMessage.iv == message.iv
          callback null,found
      else
        logger.debug "searching 30 messages from room: #{room} for duplicates"
        #check last 30 for dupes
        getMessages room, 30, (err,data) ->
          return callback err if err
          found = _.find data, (checkMessageJSON) ->
            checkMessage = JSON.parse(checkMessageJSON)
            if checkMessage.id? and message.id?
              logger.debug "comparing ids"
              checkMessage.id == message.id
            else
              logger.debug "comparing ivs"
              checkMessage.iv == message.iv
          callback null, found
    else
      callback null, false

  getNextMessageId = (room, id, callback) ->
    return callback id if id?
    #INCR message id
    rc.incr room + ":id", (err, newId) ->
      if err?
        logger.error "ERROR: getNextMessageId, room: #{room}, error: #{err}"
        callback null
      else
        callback newId





  createAndSendMessage = (from,to,iv,data,mimeType, id) ->
    logger.debug "new message"
    message = {}
    message.to = to
    message.from = from
    message.iv = iv
    message.data = data
    message.mimeType = mimeType
    message.datetime = Date.now()

    #INCR message id
    getNextMessageId room, id, (id)->
      return unless id?
      message.id = id

      logger.debug "sending message, id:  " + id + ", iv: " + iv + ", data: " + data + " to user:" + to
      newMessage = JSON.stringify(message)

      #store messages in sorted sets
      rc.zadd "messages:" + room, id, newMessage, (err, addcount) ->
        if err?
          logger.error ("ERROR: Socket.io onmessage, " + err)
          return

        #if this is the first message, add the "room" to the user's list of rooms
        if (id == 1)
          rc.sadd "conversations:"+from, room, (err,data) ->
            if err?
              logger.error ("ERROR: Socket.io onmessage, " + err)
              return

            rc.sadd "conversations:"+to, room, (err,data) ->
              if err
                logger.error ("ERROR: Socket.io onmessage, " + err)
                return

        sio.sockets.to(to).emit "message", newMessage
        sio.sockets.to(from).emit "message", newMessage

        #send gcm message
        userKey = "users:" + to
        rc.hget userKey, "gcmId", (err, gcm_id) ->
          if err?
            logger.error ("ERROR: Socket.io onmessage, " + err)
            return

          if gcm_id?.length > 0
            logger.debug "sending gcm message"
            gcmmessage = new gcm.Message()
            sender = new gcm.Sender("AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ")
            gcmmessage.addData("type", "message")
            gcmmessage.addData("to", message.to)
            gcmmessage.addData("sentfrom", message.from)
            #todo add data? (won't be large when image is a url)
            # gcmmessage.addData("data", message.data)

            gcmmessage.addData("mimeType", message.mimeType)
            gcmmessage.delayWhileIdle = true
            gcmmessage.timeToLive = 3
            gcmmessage.collapseKey = "message"
            regIds = [gcm_id]

            sender.send gcmmessage, regIds, 4, (result) ->
              logger.debug "sendGcm result: #{result}"
          else
            logger.debug "no gcm id for #{to}"

  room = sio.on "connection", (socket) ->
    user = socket.handshake.session.passport.user

    #join user's room
    logger.debug "user #{user} joining socket.io room"
    socket.join(user)

    socket.on "message", (data) ->

      user = socket.handshake.session.passport.user

      #todo check user == message.from
      #todo check from and to exist and are friends
      message = JSON.parse(data)

      # message.user = user
      logger.debug "sending message from user #{user}"

      to = message.to
      from = message.from
      cipherdata = message.data
      iv = message.iv
      resendId = message.resendId
      mimeType = message.mimeType
      room = getRoomName(from, to)

      #check for dupes if message has been resent
      checkForDuplicateMessage resendId, room, message, (err, found) ->
        if (found)
          logger.debug "found duplicate, not adding to db"
          sio.sockets.to(to).emit "message", found
          sio.sockets.to(from).emit "message", found
        else
          createAndSendMessage from, to, iv, cipherdata, mimeType


  app.post "/images/:remoteuser", ensureAuthenticated, (req,res,next) ->
    #create a message and send it to chat recipients
    room = getRoomName req.user.username, req.params.remoteuser
    getNextMessageId room, null, (id) ->
      return unless id?
      #todo env var for base location
      relUri = "/images/" + room
      newPath = __dirname + "/static" + relUri
      mkdirp newPath, (err) ->
        filename = newPath + "/#{id}"
        relUri += "/#{id}"
        return next err if err
        ins = fs.createReadStream req.files.image.path
        out = fs.createWriteStream filename
        ins.pipe out
        ins.on "end", ->
          createAndSendMessage req.user.username, req.params.remoteuser, req.files.image.name, relUri, "image/", id
          fs.unlinkSync req.files.image.path
          res.send 202, { 'Location': relUri }

  oneYear = 31557600000
  staticMiddleware = express["static"](__dirname + "/static", { maxAge: oneYear})

  app.get "/images/:room/:id",  ensureAuthenticated, (req,res,next) ->
    #todo validate user is a member of this room
    #req.url = "/images/" + req.params.room + "/" + req.params.id
    #authenticate but use static so we can use http caching
     staticMiddleware req,res,next



  #get last x messages
  app.get "/messages/:remoteuser", ensureAuthenticated, setNoCache, (req, res, next) ->
    #todo make sure they are friends
    #return last x messages
    getMessages getRoomName(req.user.username, req.params.remoteuser), 30, (err, data) ->
#    rc.zrange "messages:" + getRoomName(req.user.username, req.params.remoteuser), -50, -1, (err, data) ->
      return next err if err?
      res.send data


  #get remote messages since id
  app.get "/messages/:remoteuser/after/:messageid", ensureAuthenticated, setNoCache, (req, res, next) ->
    #return messages since id
    getMessagesAfterId getRoomName(req.user.username, req.params.remoteuser), req.params.messageid, (err, data) ->
      return next err if err?
      res.send data

  #get remote messages before id
  app.get "/messages/:remoteuser/before/:messageid", ensureAuthenticated, setNoCache, (req, res, next) ->
    #return messages since id
    getMessagesBeforeId getRoomName(req.user.username, req.params.remoteuser), req.params.messageid, (err, data) ->
      return next err if err?
      res.send data

  #get last message ids of conversations
  app.get "/conversations/ids", ensureAuthenticated, setNoCache, (req, res, next) ->
    rc.smembers "conversations:" + req.user.username, (err, conversations) ->
      return next err if err?
      if (conversations.length > 0)
        conversationsWithId = _.map conversations, (conversation) -> conversation + ":id"
        rc.mget conversationsWithId, (err, ids) ->
          return next err if err?
          some = {}
          _.each conversations, (conversation,i) -> some[getOtherUser conversation,req.user.username] = ids[i]
          res.send some
      else
          res.send 204


  app.get "/test", (req, res) ->
    res.sendfile path.normalize __dirname + "/../assets/html/test.html"

  app.get "/", (req, res) ->
    res.sendfile path.normalize __dirname + "/../assets/html/layout.html"


  app.get "/publickey/:username", ensureAuthenticated, setCache(30*oneYear), getPublicKey

  app.get "/users/:username/exists", setNoCache, (req, res) ->
    userExists req.params.username, (err, exists) ->
      return next err if err?
      res.send exists


  app.post "/login", passport.authenticate("local"), (req, res) ->
    logger.debug "/login post"
    res.send 204

  app.post "/users", createNewUserAccount, passport.authenticate("local"), (req, res) ->
    res.send 201

  app.post "/registergcm", ensureAuthenticated, (req, res) ->
    gcmId = req.body.gcmId
    userKey = "users:" + req.user.username
    rc.hset userKey, "gcmId", gcmId, (err) ->
      return next err if err?
      res.send 204

  app.post "/invite/:friendname", ensureAuthenticated, (req, res, next) ->
    friendname = req.params.friendname
    # the caller wants to add himself as a friend
    username = req.user.username
    spot = req.body.spot

    logger.debug "#{username} inviting #{friendname} to be friends"
    #todo check both users exist
    userExists friendname, (err, exists) ->
      return next err if err?
      unless exists?
        logger.debug "no such user"
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
                      logger.error ("ERROR: " + err)
                      next new Error("No gcm key.")

                    if gcmId and gcmId.length > 0
                      logger.debug "sending gcm notification"
                      gcmmessage = new gcm.Message()
                      sender = new gcm.Sender("AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ")
                      gcmmessage.addData("type", "invite")
                      gcmmessage.addData("user", username)
                      gcmmessage.delayWhileIdle = true
                      gcmmessage.timeToLive = 3
                      gcmmessage.collapseKey = "invite"
                      regIds = [gcmId]

                      sender.send gcmmessage, regIds, 4, (result) ->
                        logger.debug(result)
                        res.send 204
                    else
                      logger.debug "gcmId not set for #{friendname}"
                else
                  res.send 403


  app.post '/invites/:friendname/:action', ensureAuthenticated, (req, res, next) ->
    logger.debug 'POST /invites'
    username = req.user.username
    friendname = req.params.friendname
    accept = req.params.action is 'accept'
    #todo use transaction?
    rc.srem "invited:#{friendname}", username, (err, data) ->
      return next new Error("[friend] srem failed for invited:#{friendname}: " + username) if err?
      rc.srem "invites:#{username}", friendname, (err, data) ->
        #send to room
        #TOdo push\
        if accept
          rc.sadd "friends:#{username}", friendname, (err, data) ->
            return next new Error("[friend] sadd failed for username: " + username + ", friendname" + friendname) if err?
            rc.sadd "friends:#{friendname}", username, (err, data) ->
              return next new Error("[friend] sadd failed for username: " + friendname + ", friendname" + username) if err?
              sio.sockets.to(friendname).emit "inviteResponse",JSON.stringify { user: username, response: req.params.action }

              if (req.params.action == "accept")
                userKey = "users:" + friendname
                rc.hget userKey, "gcmId", (err, gcmId) ->
                  if err?
                    logger.error ("ERROR: " + err)
                    next new Error("No gcm key.")

                  if gcmId and gcmId.length > 0
                    logger.debug "sending gcm notification"

                    gcmmessage = new gcm.Message()
                    sender = new gcm.Sender("AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ")
                    gcmmessage.addData("type", "inviteResponse")
                    gcmmessage.addData("user", username)
                    gcmmessage.addData("response", req.params.action)
                    gcmmessage.delayWhileIdle = true
                    gcmmessage.timeToLive = 3
                    gcmmessage.collapseKey = "inviteResponse"
                    regIds = [gcmId]

                    sender.send gcmmessage, regIds, 4, (result) ->
                      logger.debug(result)
                      res.send 204
                  else
                    logger.debug "gcmId not set for #{friendname}"
                    res.send 204

        else
          rc.sadd "ignores:#{username}", friendname, (err, data) ->
            return next new Error("[friend] sadd failed for username: " + username + ", friendname" + friendname) if err?
            sio.sockets.to(friendname).emit "inviteResponse", JSON.stringify { user: username, response: req.params.action }
            res.send 204



  getFriends = (req, res, next) ->
    username = req.user.username

    dal.getFriends username, (err, rfriends) ->
      return next err if err?
      friends = []
      _.each rfriends, (name) -> friends.push {status: "friend", name: name}

      rc.smembers "invites:#{username}", (err, invites) ->
        return next err if err?
        _.each invites, (name) -> friends.push {status: "invitee", name: name}

        rc.smembers "invited:#{username}", (err, invited) ->
          return next err if err?
          _.each invited, (name) -> friends.push {status: "invited", name: name}
          logger.debug ("friends: " + friends)
          res.send friends
  app.get "/friends", ensureAuthenticated, setNoCache, getFriends


  app.post "/logout", ensureAuthenticated, (req, res) ->
    req.logout()
    res.send 204


  process.on "uncaughtException", uncaught = (err) ->
    logger.error "Uncaught Exception: ", err

  passport.use new LocalStrategy (username, password, done) ->
    userKey = "users:" + username
    logger.debug "looking for: " + userKey
    logger.debug "password: " + password
    rc.hgetall userKey, (err, user) ->
      return done(err)  if err?
      unless user
        return done(null, false,
          message: "Unknown user"
        )
      logger.debug "user.password: " + user.password
      bcrypt.compare password, user.password, (err, res) ->
        return fn(new Error("[bcrypt.compare] failed with error: " + err))  if err?
        logger.debug res
        return done(null, user)  if res is true
        done null, false,
          message: "Invalid password"




  passport.serializeUser (user, done) ->
    logger.debug "serializeUser, username: " + user.username
    done null, user.username

  passport.deserializeUser (username, done) ->
    logger.debug "deserializeUser, user:" + username
    rc.hgetall "users:" + username, (err, user) ->
      done err, user
