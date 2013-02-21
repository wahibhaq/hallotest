cluster = require('cluster')
http = require('http')
numCPUs = require('os').cpus().length

if (cluster.isMaster)
  # Fork workers.
  for i in [0..numCPUs-1]
    cluster.fork();

  cluster.on 'online', (worker, code, signal) ->
    console.log 'worker ' + worker.process.pid + ' online'

  cluster.on 'exit', (worker, code, signal) ->
    console.log 'worker ' + worker.process.pid + ' died'

else

  requirejs = require 'requirejs'
  requirejs.config {
  ##appDir: '.'
  nodeRequire: require
  #  paths:
  #    {
  #      'cs': 'cs'
  #    }
  }



  requirejs ['cs!dal', 'underscore', 'winston'], (DAL, _, winston) ->
    http = require 'http'
    cookie = require("cookie")
    express = require("express")
    passport = require("passport")
    LocalStrategy = require("passport-local").Strategy
    crypto = require 'crypto'
    RedisStore = require("connect-redis")(express)
    path = require 'path'
    util = require("util")
    gcm = require("node-gcm")
    fs = require("fs")
    bcrypt = require 'bcrypt'
    dcrypt = require 'dcrypt'
    mkdirp = require("mkdirp")
    expressWinston = require "express-winston"
    logger = require("winston")

    logger.remove winston.transports.Console
    logger.setLevels winston.config.syslog.levels

    transports = [
      new (winston.transports.Console)({colorize: true, timestamp: true, level: 'info' }),
      new (winston.transports.File)({ filename: 'logs/server.log', maxsize: 1024576, maxFiles: 20, json: false, level: 'info' })]

    logger.add transports[0], null, true
    logger.add transports[1], null, true

    process.on "uncaughtException", uncaught = (err) ->
      logger.error "Uncaught Exception: " + err


    nodePort = 443
    socketPort = 443
    sio = undefined
    sessionStore = undefined
    rc = undefined
    rcs = undefined
    pub = undefined
    sub = undefined
    client = undefined
    dal = undefined
    app = undefined
    ssloptions = undefined
    connectionCount = 0

    createRedisClient = (port, hostname, password, database) ->
      if port? and hostname? and password?
        client = require("redis").createClient(port, hostname)
        client.auth password
        if database?
          client.select database, (err, res) ->
            return client
        else
          return client


      else
        client = require("redis").createClient()
        if database?
          client.select database, (err, res) ->
            return client
        else
          return client


    logger.debug "process.env.NODE_ENV: " + process.env.NODE_ENV
    logger.debug "process.env.NODE_SSL: " + process.env.NODE_SSL
    logger.debug "__dirname: #{__dirname}"
    dev = process.env.NODE_ENV != "linode"
    nossl = process.env.NODE_NOSSL is "true"
    database = process.env.NODE_DB
    if database is null
      database = 0


    logger.debug "database: #{database}"


    if not dev
      ssloptions = {
      key: fs.readFileSync('ssl/surespot.key'),
      cert: fs.readFileSync('ssl/www_surespot_me.crt'),
      ca: fs.readFileSync('ssl/PositiveSSLCA2.crt')
      }
    else
      ssloptions = {
      key: fs.readFileSync('ssllocal/local.key'),
      cert: fs.readFileSync('ssllocal/local.crt')
      }

    # create EC keys like so
    # priv key
    # openssl ecparam -name secp521r1 -outform PEM -out priv.pem -genkey
    # pub key
    # openssl ec -inform PEM  -outform PEM -in priv.pem -out pub.pem -pubout
    #
    # verify signature like so
    # openssl dgst -sha256 -verify key -signature sig.bin data


    serverPrivateKey = fs.readFileSync('ec/priv.pem')
    #serverPublicKey = fs.readFileSync('ec/pub.pem')


    if nossl
      app = module.exports = express.createServer()
    else
      app = module.exports = express.createServer ssloptions



    app.configure ->
      if nossl
        nodePort = 3000
        socketPort = 3000
      sessionStore = new RedisStore()
      dal = new DAL()
      rc = createRedisClient database
      rcs = createRedisClient database
      pub = createRedisClient database
      sub = createRedisClient database
      client = createRedisClient database

    app.configure "amazon-stage", ->
      logger.debug "running on amazon-stage"
      nodePort = 443
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
      rcs = createRedisClient(redisPort, redisHost, redisAuth)
      pub = createRedisClient(redisPort, redisHost, redisAuth)
      sub = createRedisClient(redisPort, redisHost, redisAuth)
      client = createRedisClient(redisPort, redisHost, redisAuth)


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
      transports: transports
      })
      app.use app.router
      app.use expressWinston.errorLogger({
      transports: transports
      })


      app.use express.errorHandler({
      showMessage: true,
      showStack: false,
      dumpExceptions: false
      })

    http.globalAgent.maxSockets = Infinity;

    app.listen nodePort, null
    #app.maxHeadersCount = 4096
    if nodePort == socketPort
      sio = require("socket.io").listen app
    else
      sio = require("socket.io").listen socketPort

    #sio.configure "amazon-stage", ->


    #winston up some socket.io
    sio.set "logger", {debug: logger.debug, info: logger.info, warn: logger.warning, error: logger.error }
    sio.configure 'load testing', 'linode', ->
      sio.set 'close timeout', 180
      sio.set 'heartbeat timeout', 180
      sio.set 'heartbeat interval', 160
      sio.set 'polling duration', 150

    sioRedisStore = require("socket.io/lib/stores/redis")
    sio.set "store", new sioRedisStore(
      redisPub: pub
      redisSub: sub
      redisClient: client
    )

    sio.set 'transports', ['websocket']

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

    setNoCache = (req, res, next) ->
      res.setHeader "Cache-Control", "no-cache"
      next()

    setCache = (seconds) -> (req, res, next) ->
      res.setHeader "Cache-Control", "public, max-age=#{seconds}"
      next()

    userExists = (username, fn) ->
      userKey = "users:" + username
      rc.hlen userKey, (err, hlen) ->
        return fn(new Error("[userExists] failed for user: " + username)) if err
        fn null, hlen > 0

    validateUsernameExists = (req, res, next) ->
      userExists req.params.username, (err, exists) ->
        return next err if err?
        if not exists
          res.send 404
        else
          next()

    validateAreFriends = (req, res, next) ->
      username = req.user.username
      friendname = req.params.username
      dal.isFriend username, friendname, (err, result) ->
        return next err if err?
        if result
          next()
        else
          res.send 403

    getRoomName = (from, to) ->
      if from < to then from + ":" + to else to + ":" + from

    getOtherUser = (room, user) ->
      users = room.split ":"
      if user == users[0] then return users[1] else return users[0]

    getPublicIdentity = (req, res, next) ->
      if req.params.username
        username = req.params.username
        rc.hgetall "users:" + username, (err, data) ->
          return next err if err
          if data?
            #todo use properly
            res.setHeader "Cache-Control", "public, max-age=#{oneYear}"
            user = {}
            user.username = data.username
            user.dhPub = data.dhPub
            user.dsaPub = data.dsaPub
            user.dsaPubSig = data.dsaPubSig
            user.dhPubSig = data.dhPubSig
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
      rc.zrangebyscore "messages:" + room, "(" + id, "+inf", (err, data) ->
        return fn err if err?
        fn null, data

    getMessagesBeforeId = (room, id, fn) ->
      rc.zrangebyscore "messages:" + room, id - 30, "(" + id, (err, data) ->
        return fn err if err?
        fn null, data

    createNewUserAccount = (req, res, next) ->

      username = req.body.username
      logger.debug "createNewUserAccount: #{username}"

      #var newUser = {name:name, email:email };
      userExists username, (err, exists) ->
        return next err if err?
        if exists
          logger.debug "user already exists"
          res.send 409
        else
          password = req.body.password

          user = {}
          user.username = req.body.username

          if req.body.dhPub?
            user.dhPub = req.body.dhPub
          else
            return next new Error('dh public key required')

          if req.body.dsaPub?
            user.dsaPub = req.body.dsaPub
          else
            return next new Error('dsa public key required')

          if req.body.authSig is null
            return next new Error('auth signature required')

          if req.body.gcmId?
            user.gcmId = req.body.gcmId

          #dump the key stuff to a file
          #        key = '-----BEGIN PUBLIC KEY-----\n' + req.body.dhPub + '-----END PUBLIC KEY-----\n'
          #        fs.writeFileSync "#{user.username}.sig", user.authSig
          #        fs.writeFileSync "#{user.username}.key", key
          #        fs.writeFileSync "#{user.username}.data", user.username
          logger.debug "gcmID: #{user.gcmId}"

          bcrypt.genSalt 10, (err, salt) ->
            return next err if err?
            bcrypt.hash password, salt, (err, password) ->
              return next err if err?
              user.password = password

              #sign the keys
              user.dhPubSig = crypto.createSign('sha256').update(new Buffer(user.dhPub)).sign(serverPrivateKey, 'base64')
              user.dsaPubSig = crypto.createSign('sha256').update(new Buffer(user.dsaPub)).sign(serverPrivateKey, 'base64')
              logger.debug "#{user.username}, dhPubSig: #{user.dhPubSig}, dsaPubSig: #{user.dsaPubSig}"

              userKey = "users:" + user.username
              rc.hmset userKey, user, (err, data) ->
                logger.debug "set " + userKey + " in db"
                return next new Error("[createNewUserAccount] SET failed for user: " + username) if err?
                req.login user, ->
                  req.user = user
                  next()

    checkForDuplicateMessage = (resendId, room, message, callback) ->
      if (resendId?)
        if (resendId > 0)
          logger.debug "searching room: #{room} from id: #{resendId} for duplicate messages"
          #check messages client doesn't have for dupes
          getMessagesAfterId room, resendId, (err, data) ->
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
          logger.debug "searching 30 messages from room: #{room} for duplicates"
          #check last 30 for dupes
          getMessages room, 30, (err, data) ->
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

    createAndSendMessage = (from, to, iv, data, mimeType, id) ->
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
            rc.sadd "conversations:" + from, room, (err, data) ->
              if err?
                logger.error ("ERROR: Socket.io onmessage, " + err)
                return

              rc.sadd "conversations:" + to, room, (err, data) ->
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
              gcmmessage.collapseKey = "message:#{getRoomName(message.from, message.to)}"
              regIds = [gcm_id]

              sender.send gcmmessage, regIds, 4, (result) ->
                logger.debug "sendGcm result: #{result}"
            else
              logger.debug "no gcm id for #{to}"

    room = sio.on "connection", (socket) ->
      user = socket.handshake.session.passport.user
      logger.info 'connections: ' + connectionCount++

      #join user's room
      logger.debug "user #{user} joining socket.io room"
      socket.join user
      socket.on "message", (data) ->
        user = socket.handshake.session.passport.user

        #todo check from and to exist and are friends
        message = JSON.parse(data)

        # message.user = user
        logger.debug "sending message from user #{user}"

        to = message.to
        return if to is null
        from = message.from
        return if from is null
        #if this message isn't from the logged in user we have problems
        if user isnt from then socket.disconnect()
        userExists from, (err, exists) ->
          return if err?
          if exists
            #if they're not friends disconnect them, wtf are they trying to do here?
            dal.isFriend user, to, (err, isFriend) ->
              return if err?
              return socket.disconnect() if not isFriend
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


    app.post "/images/:username", ensureAuthenticated, validateUsernameExists, validateAreFriends, (req, res, next) ->
      #create a message and send it to chat recipients
      room = getRoomName req.user.username, req.params.username
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
            createAndSendMessage req.user.username, req.params.username, req.files.image.name, relUri, "image/", id
            fs.unlinkSync req.files.image.path
            res.send 202, { 'Location': relUri }

    oneYear = 31557600000
    staticMiddleware = express["static"](__dirname + "/static", { maxAge: oneYear})

    app.get "/images/:room/:id", ensureAuthenticated, (req, res, next) ->
      username = req.user.username
      room = req.params.room
      users = room.split ":"
      if users.length != 2
        return next new Error "Invalid room name."

      otherUser = getOtherUser room, username
      dal.isFriend username, otherUser, (err, result) ->
        return res.send 403 if not result

        #req.url = "/images/" + req.params.room + "/" + req.params.id
        #authenticate but use static so we can use http caching
        staticMiddleware req, res, next

    #get last x messages
    app.get "/messages/:username", ensureAuthenticated, validateUsernameExists, validateAreFriends, setNoCache, (req, res, next) ->
      #return last x messages
      getMessages getRoomName(req.user.username, req.params.username), 30, (err, data) ->
        #    rc.zrange "messages:" + getRoomName(req.user.username, req.params.remoteuser), -50, -1, (err, data) ->
        return next err if err?
        res.send data


    #get remote messages since id
    app.get "/messages/:username/after/:messageid", ensureAuthenticated, validateUsernameExists, validateAreFriends, setNoCache, (req, res, next) ->
      #return messages since id
      getMessagesAfterId getRoomName(req.user.username, req.params.username), req.params.messageid, (err, data) ->
        return next err if err?
        res.send data

    #get remote messages before id
    app.get "/messages/:username/before/:messageid", ensureAuthenticated, validateUsernameExists, validateAreFriends, setNoCache, (req, res, next) ->
      #return messages since id
      getMessagesBeforeId getRoomName(req.user.username, req.params.username), req.params.messageid, (err, data) ->
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
            _.each conversations, (conversation, i) -> some[getOtherUser conversation, req.user.username] = ids[i]
            res.send some
        else
          res.send 204


    #app.get "/test", (req, res) ->
    # res.sendfile path.normalize __dirname + "/../assets/html/test.html"

    #app.get "/", (req, res) ->
    # res.sendfile path.normalize __dirname + "/../assets/html/layout.html"

    app.get "/publicidentity/:username", ensureAuthenticated, validateUsernameExists, validateAreFriends, setCache(30 * oneYear), getPublicIdentity

    app.get "/users/:username/exists", setNoCache, (req, res, next) ->
      userExists req.params.username, (err, exists) ->
        return next err if err?
        res.send exists

    app.post "/login", passport.authenticate("local"), (req, res, next) ->
      logger.debug "/login post"
      res.send 204

    app.post "/users", createNewUserAccount, passport.authenticate("local"), (req, res, next) ->
      res.send 201

    app.post "/validate", (req, res, next) ->
      username = req.body.username
      password = req.body.password
      authSig = req.body.authSig

      validateUser username, password, authSig, (err, status, user) ->
        return next err if err?
        res.send status

    app.post "/registergcm", ensureAuthenticated, (req, res, next) ->
      gcmId = req.body.gcmId
      userKey = "users:" + req.user.username
      rc.hset userKey, "gcmId", gcmId, (err) ->
        return next err if err?
        res.send 204

    app.post "/invite/:username", ensureAuthenticated, validateUsernameExists, (req, res, next) ->
      friendname = req.params.username
      username = req.user.username

      # the caller wants to add himself as a friend
      if friendname is username then return res.send 403

      logger.debug "#{username} inviting #{friendname} to be friends"
      #todo check if friendname has ignored username
      #see if they are already friends
      dal.isFriend username, friendname, (err, result) ->
        #if they are, do nothing
        if result then res.send 409
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
                    return next new Error err

                  if gcmId?.length > 0
                    logger.debug "sending gcm notification"
                    gcmmessage = new gcm.Message()
                    sender = new gcm.Sender("AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ")
                    gcmmessage.addData "type", "invite"
                    gcmmessage.addData "sentfrom", username
                    gcmmessage.addData "to", friendname
                    gcmmessage.delayWhileIdle = true
                    gcmmessage.timeToLive = 3
                    gcmmessage.collapseKey = "invite:#{friendname}"
                    regIds = [gcmId]

                    sender.send gcmmessage, regIds, 4, (result) ->
                      #logger.debug(result)
                      res.send 204
                  else
                    logger.debug "gcmId not set for #{friendname}"
                    res.send 204
              else
                res.send 403


    app.post '/invites/:username/:action', ensureAuthenticated, (req, res, next) ->
      logger.debug 'POST /invites'
      username = req.user.username
      friendname = req.params.username

      #make sure invite exists
      dal.inviteExists friendname, username, (err, result) ->
        return next err if err?
        return res.send 404 if not result
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
                  sio.sockets.to(friendname).emit "inviteResponse", JSON.stringify { user: username, response: req.params.action }

                  if (req.params.action == "accept")
                    userKey = "users:" + friendname
                    rc.hget userKey, "gcmId", (err, gcmId) ->
                      if err?
                        logger.error ("ERROR: " + err)
                        return next new Error err

                      if gcmId?.length > 0
                        logger.debug "sending gcm notification"

                        gcmmessage = new gcm.Message()
                        sender = new gcm.Sender("AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ")
                        gcmmessage.addData("type", "inviteResponse")
                        gcmmessage.addData "sentfrom", username
                        gcmmessage.addData "to", friendname
                        gcmmessage.addData("response", req.params.action)
                        gcmmessage.delayWhileIdle = true
                        gcmmessage.timeToLive = 3
                        gcmmessage.collapseKey = "inviteResponse:#{friendname}"
                        regIds = [gcmId]

                        sender.send gcmmessage, regIds, 4, (result) ->
                          #logger.debug(result)
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


    comparePassword = (password, dbpassword, callback) ->
      bcrypt.compare password, dbpassword, callback


    validateUser = (username, password, signature, done) ->
      return done(null, 403) if signature.length < 16
      userKey = "users:" + username
      logger.debug "validating: " + username
      rcs.hgetall userKey, (err, user) ->
        return done(err) if err?
        return done null, 404 if not user
        comparePassword password, user.password, (err, res) ->
          return done err if err?
          return done null, 403 if not res

          #get the signature
          buffer = new Buffer(signature, 'base64')

          #random is stored in first 16 bytes
          random = buffer.slice 0, 16
          signature = buffer.slice 16

          verified = crypto.createVerify('sha256').update(new Buffer(username)).update(new Buffer(password)).update(random).verify(user.dsaPub, signature)
          logger.debug "validated, #{username}: #{verified}"

          status = if verified then 204 else 403
          done null, status, if verified then user else null


    passport.use new LocalStrategy ({passReqToCallback: true}), (req, username, password, done) ->
      signature = req.body.authSig
      validateUser username, password, signature, (err, status, user) ->
        return done(err) if err?

        switch status
          when 404 then return done null, false, message: "unknown user"
          when 403 then return done null, false, message: "invalid password or key"
          when 204 then return done null, user
          else
            return new Error 'unknown validation status: #{status}'

    passport.serializeUser (user, done) ->
      logger.debug "serializeUser, username: " + user.username
      done null, user.username

    passport.deserializeUser (username, done) ->
      logger.debug "deserializeUser, user:" + username
      rcs.hgetall "users:" + username, (err, user) ->
        done err, user

