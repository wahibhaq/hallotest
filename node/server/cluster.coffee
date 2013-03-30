cluster = require('cluster')
http = require('http')
numCPUs = require('os').cpus().length
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
mkdirp = require("mkdirp")
expressWinston = require "express-winston"
logger = require("winston")
async = require 'async'
shortid = require 'shortid'
_ = require 'underscore'
querystring = require 'querystring'
request = require 'request'

logger.remove logger.transports.Console
logger.setLevels logger.config.syslog.levels

transports = []
transports.push new (logger.transports.File)({ dirname: 'logs', filename: 'server.log', maxsize: 1024576, maxFiles: 20, json: false, level: 'debug' })
#always use file transport
logger.add transports[0], null, true


nossl = process.env.NODE_NOSSL is "true"
database = process.env.NODE_DB
socketPort = process.env.SOCKET
dev = process.env.NODE_ENV != "linode"

if dev
  transports.push new (logger.transports.Console)({colorize: true, timestamp: true, level: 'debug' })
  logger.add transports[1], null, true
  numCPUs = 1

logger.debug "process.env.NODE_ENV: " + process.env.NODE_ENV
logger.debug "process.env.NODE_SSL: " + process.env.NODE_SSL
logger.debug "__dirname: #{__dirname}"


if (cluster.isMaster && !dev)
  # Fork workers.
  for i in [0..1 - numCPUs]
    cluster.fork();

  cluster.on 'online', (worker, code, signal) ->
    logger.debug 'worker ' + worker.process.pid + ' online'

  cluster.on 'exit', (worker, code, signal) ->
    logger.debug 'worker ' + worker.process.pid + ' died'

else

  database = 0 unless database?
  socketPort = 443 unless socketPort?

  logger.info "dev: #{dev}"
  logger.info "database: #{database}"
  logger.info "socket: #{socketPort}"

  process.on "uncaughtException", uncaught = (err) ->
    logger.error "Uncaught Exception: " + err

  sio = undefined
  sessionStore = undefined
  rc = undefined
  rcs = undefined
  pub = undefined
  sub = undefined
  client = undefined
  app = undefined
  ssloptions = undefined
  connectionCount = 0
  googleApiKey = 'AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ'


  createRedisClient = (callback, database, port, hostname, password) ->
    if port? and hostname? and password?
      client = require("redis").createClient(port, hostname)
      client.auth password
      if database?
        client.select database, (err, res) ->
          return callback err if err?
          callback null, client

      else
        callback null, client
    else
      client = require("redis").createClient()
      if database?
        client.select database, (err, res) ->
          return callback err if err?
          callback null, client
      else
        callback null, client

  serverPrivateKey = undefined

  if not dev
    ssloptions = {
    key: fs.readFileSync('ssl/surespot.key'),
    cert: fs.readFileSync('ssl/www_surespot_me.crt'),
    ca: fs.readFileSync('ssl/PositiveSSLCA2.crt')
    }
    serverPrivateKey = fs.readFileSync('ecprod/priv.pem')
  else
    ssloptions = {
    key: fs.readFileSync('ssllocal/local.key'),
    cert: fs.readFileSync('ssllocal/local.crt')
    }
    serverPrivateKey = fs.readFileSync('ecdev/priv.pem')

  # create EC keys like so
  # priv key
  # openssl ecparam -name secp521r1 -outform PEM -out priv.pem -genkey
  # pub key
  # openssl ec -inform PEM  -outform PEM -in priv.pem -out pub.pem -pubout
  #
  # verify signature like so
  # openssl dgst -sha256 -verify key -signature sig.bin data



  #serverPublicKey = fs.readFileSync('ec/pub.pem')


  if nossl
    app = module.exports = express.createServer()
  else
    app = module.exports = express.createServer ssloptions


  app.configure ->
    if nossl
      socketPort = 3000
    sessionStore = new RedisStore({db: database})
    createRedisClient ((err, c) -> rc = c), database
    createRedisClient ((err, c) -> rcs = c), database
    createRedisClient ((err, c) -> pub = c), database
    createRedisClient ((err, c) -> sub = c), database
    createRedisClient ((err, c) -> client = c), database

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

    app.use(expressWinston.errorLogger({
    transports: transports
    }))
    app.use(express.errorHandler({
    showMessage: true,
    showStack: true,
    dumpExceptions: true
    }))


  http.globalAgent.maxSockets = Infinity;

  app.listen socketPort, null
  sio = require("socket.io").listen app


  #winston up some socket.io
  sio.set "logger", {debug: logger.debug, info: logger.info, warn: logger.warning, error: logger.error }


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
          accept null, false
        else
          req.session = session
          if req.session.passport.user
            accept null, true
          else
            accept null, false
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


  checkUser = (username) ->
    return username?.length > 0 and username?.length  <= 24


  checkPassword = (password) ->
    return password?.length > 0 and password?.length  <= 2048


  validateUsernamePassword = (req, res, next) ->
    username = req.body.username
    password = req.body.password

    if !checkUser(username) or !checkPassword(password)
      res.send 403
    else
      next()

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
    isFriend username, friendname, (err, result) ->
      return next err if err?
      if result
        next()
      else
        res.send 403

  validateAreFriendsOrDeleted = (req, res, next) ->
    username = req.user.username
    friendname = req.params.username
    isFriend username, friendname, (err, result) ->
      return next err if err?
      if result
        next()
      else
        #if we're not friends check if he deleted himself
        rc.sismember "users:deleted:#{username}", friendname, (err, isDeleted) ->
          return next err if err?
          if isDeleted
            next()
          else
            res.send 403

  validateAreFriendsOrDeletedOrInvited = (req, res, next) ->
    username = req.user.username
    friendname = req.params.username

    isFriend username, friendname, (err, result) ->
      return next err if err?
      if result
        next()
      else
        #we've been deleted
        rc.sismember "users:deleted:#{username}", friendname, (err, isDeleted) ->
          return next err if err?
          if isDeleted
            next()
          else
            #we invited someone
            rc.sismember "invited:#{username}", friendname, (err, isInvited) ->
              return next err if err?
              if isInvited
                next()
              else
                res.send 403


  #is friendname a friend of username
  isFriend = (username, friendname, callback) ->
    rc.sismember "friends:#{username}", friendname, callback

  hasConversation = (username, room, callback) ->
    rc.sismember "conversations:#{username}", room, callback

  inviteExists = (username, friendname, callback) ->
    rc.sismember "invited:#{username}", friendname, (err, result) =>
      return callback err if err?
      return callback null, false if not result
      rc.sismember "invites:#{friendname}", username, callback

  getRoomName = (from, to) ->
    if from < to then from + ":" + to else to + ":" + from

  getOtherUser = (room, user) ->
    users = room.split ":"
    if user == users[0] then return users[1] else return users[0]

  getPublicKeys = (req, res, next) ->
    username = req.params.username
    version = req.params.version

    if version?
      rc.hgetall "keys:#{username}:#{version}", (err, keys) ->
        return next err if err?
        return res.send keys
    else
      getLatestKeys username, (err, keys) ->
        return next err if err
        res.send keys

  getMessage = (room, id, fn) ->
    rc.zrangebyscore "messages:" + room, id, id, (err, data) ->
      return fn err if err?
      if data.length is 1
        fn null, JSON.parse(data[0])
      else
        fn null, null

  removeMessage = (to, room, id, fn) ->
    rc.zremrangebyscore "messages:" + room, id, id, (err, message) ->
      return fn err if err?
      rc.srem "deleted:#{to}:#{room}", id, fn

  filterDeletedMessages = (username, room, messages, callback) ->
    rc.smembers "deleted:#{username}:#{room}", (err, deleted) ->
      scoredMessages = []
      sendMessages = []
      index = 0
      for index in [0..messages.length-1] by 2
        scoredMessages.push { id: messages[index+1], message: messages[index] }

      async.each(
        scoredMessages
        (item, icallback) ->
          if not (item.id in deleted)
            sendMessages.push item.message
          icallback()
        (err) ->
          callback err if err?
          callback null, sendMessages)

  getAllEarlierMessagesInclusiveOf = (room, messageId, fn) ->
    #return last x messages
    #args = []
    rc.zrangebyscore "messages:#{room}", 0, messageId, (err, data) ->
      return fn err if err?
      fn null, data


  getMessages = (username, room, count, fn) ->
    #return last x messages
    #args = []
    rc.zrange "messages:#{room}", -count, -1, 'withscores', (err, data) ->
      return fn err if err?
      filterDeletedMessages username, room, data, (err, messages) ->
        return fn err if err?
        fn null, messages

  getControlMessages = (room, count, fn) ->
    rc.zrange "control:message:" + room, -count, -1, (err, data) ->
      return fn err if err?
      fn null, data

  getUserControlMessages = (user, count, fn) ->
    rc.zrange "control:user:" + user, -count, -1, (err, data) ->
      return fn err if err?
      fn null, data

  getMessagesAfterId = (username, room, id, fn) ->
    if id is -1
      fn null, null
    else
      if id is 0
        getMessages username, room, 30, fn
      else
        #args = []
        rc.zrangebyscore "messages:#{room}", "(" + id, "+inf", 'withscores', (err, data) ->
          filterDeletedMessages username, room, data, fn

  getMessagesBeforeId = (username, room, id, fn) ->
    rc.zrangebyscore "messages:#{room}", id - 60, "(" + id, 'withscores', (err, data) ->
      filterDeletedMessages username, room, data, fn

  checkForDuplicateMessage = (resendId, username, room, message, callback) ->
    if (resendId?)
      if (resendId > 0)
        logger.debug "searching room: #{room} from id: #{resendId} for duplicate messages"
        #check messages client doesn't have for dupes
        getMessagesAfterId username, room, resendId, (err, data) ->
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
        getMessages username, room, 30, (err, data) ->
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

  getControlMessagesAfterId = (room, id, fn) ->
    if id is -1
      fn null, null
    else
      if id is 0
        getControlMessages room, 60, fn
      else
        rc.zrangebyscore "control:message:" + room, "(" + id, "+inf", (err, data) ->
          return fn err if err?
          fn null, data

  getUserControlMessagesAfterId = (user, id, fn) ->
    if id is -1
      fn null, null
    else
      if id is 0
        getUserControlMessages user, 20, fn
      else
        rc.zrangebyscore "control:user:" + user, "(" + id, "+inf", (err, data) ->
          return fn err if err?
          fn null, data


  checkForDuplicateControlMessage = (resendId, room, message, callback) ->
    if (resendId?)
      logger.debug "searching room: #{room} from id: #{resendId} for duplicate control messages"
      #check messages client doesn't have for dupes
      getControlMessagesAfterId room, resendId, (err, data) ->
        return callback err if err
        found = _.find data, (checkMessageJSON) ->
          checkMessage = JSON.parse(checkMessageJSON)
#          checkMessage.type is message.type
#          checkMessage.action is message.action
#          checkMessage.data is message.data
#          checkMessage.moredata is message.data

          checkMessage.from is message.from
          checkMessage.localid is message.localid
        return callback(null, found)
    else
      return callback null, false



  getNextMessageId = (room, id, callback) ->
    #we will alread have an id if we uploaded a file
    return callback id if id?
    #INCR message id
    rc.incr room + ":id", (err, newId) ->
      if err?
        logger.error "ERROR: getNextMessageId, room: #{room}, error: #{err}"
        callback null
      else
        callback newId

  getNextMessageControlId = (room, callback) ->
    #INCR message id
    rc.incr "control:message:#{room}:id", (err, newId) ->
      if err?
        logger.error "ERROR: getNextMessageControlId, room: #{room}, error: #{err}"
        callback null
      else
        callback newId

  getNextUserControlId = (user, callback) ->
          #INCR message id
    rc.incr "control:user:#{user}:id", (err, newId) ->
      if err?
        logger.error "ERROR: getNextUserControlId, user: #{user}, error: #{err}"
        callback null
      else
        callback newId


  createAndSendMessage = (from, fromVersion, to, toVersion, iv, data, mimeType, id) ->
    logger.debug "new message"
    message = {}
    message.to = to
    message.from = from
    message.datetime = Date.now()
    message.toVersion = toVersion
    message.fromVersion = fromVersion
    message.iv = iv
    message.data = data
    message.mimeType = mimeType
    room = getRoomName(from,to)


    #INCR message id
    getNextMessageId room, id, (id)->
      return unless id?
      message.id = id

      logger.debug "sending message, id:  #{id}, iv: #{iv}, data: #{data}, to user: #{to}"
      newMessage = JSON.stringify(message)

      #store messages in sorted sets
      rc.zadd "messages:#{room}", id, newMessage, (err, addcount) ->
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
            sender = new gcm.Sender("#{googleApiKey}")
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

  createAndSendMessageControlMessage = (from, to, room, action, data, moredata, callback) ->
    message = {}
    message.type = "message"
    message.action = action
    message.data = data


    if moredata?
      message.moredata = moredata

    #add control message
    getNextMessageControlId room, (id) ->
      callback new Error 'could not create next message control id' unless id?
      message.id = id
      message.from = from
      sMessage = JSON.stringify message
      rc.zadd "control:message:#{room}", id, sMessage, (err, addcount) ->
        callback err if err?
        sio.sockets.to(to).emit "control", sMessage
        callback null

  createAndSendUserControlMessage = (to, action, data, moredata, callback) ->
    message = {}
    message.type = "user"
    message.action = action
    message.data = data

    if moredata?
      message.moredata = moredata

    #send control message to ourselves
    getNextUserControlId to,(id) ->
      return callback new Error 'could not get user control id' unless id?
      message.id = id
      newMessage = JSON.stringify(message)
      #store messages in sorted sets
      rc.zadd "control:user:#{to}", id, newMessage, (err, addcount) ->
        #end transaction here
        return callback err if err?
        sio.sockets.to(to).emit "control", newMessage
        callback null

  # broadcast a key revocation message to who's conversations
  sendRevokeMessages = (who, newVersion, callback) ->
    logger.debug "new message"

    logger.debug "sending user control message to #{who}: #{who} has completed a key roll"

    createAndSendUserControlMessage who, "revoke", who, newVersion, (err) ->
      logger.error ("ERROR: adding user control message, " + err) if err?
      return callback new error 'could not send user controlmessage' if err?


      #Get all the dude's conversations
      rc.smembers "conversations:#{who}", (err, convos) ->
        return callback err if err?
        async.each convos, (room, callback) ->
          to = getOtherUser(room, who)
          createAndSendUserControlMessage to, "revoke", who, newVersion, (err) ->
            logger.error ("ERROR: adding user control message, " + err) if err?
            return callback new error 'could not send user controlmessage' if err?
            callback()
        , callback


  handleMessage = (user, data) ->
    #user = socket.handshake.session.passport.user

    #todo check from and to exist and are friends
    message = JSON.parse(data)

    # message.user = user
    logger.debug "received message from user #{user}"

    to = message.to
    return unless to?
    from = message.from
    return unless from?
    toVersion = message.toVersion
    return unless toVersion?
    fromVersion = message.fromVersion
    return unless fromVersion?
    iv = message.iv
    return unless iv?

    #if this message isn't from the logged in user we have problems
    return if user isnt from #then socket.disconnect()
    userExists from, (err, exists) ->
      return if err?
      if exists
        #if they're not friends with us or we're not friends with them we have a problem
        # todo tell client not to reconnect when this happens...otherwise infinite connect loop for now we'll just do nothing
        isFriend user, to, (err, aFriend) ->
          return if err?
          #return socket.disconnect() if not aFriend
          #logger.debug "notafriend"
          return if not aFriend


          cipherdata = message.data
          resendId = message.resendId
          mimeType = message.mimeType
          room = getRoomName(from, to)

          #check for dupes if message has been resent
          checkForDuplicateMessage resendId, user, room, message, (err, found) ->
            if found
              logger.debug "found duplicate message, not adding to db"
              sio.sockets.to(to).emit "message", found
              sio.sockets.to(from).emit "message", found
            else
              createAndSendMessage from, fromVersion, to, toVersion, iv, cipherdata, mimeType


  room = sio.on "connection", (socket) ->
    user = socket.handshake.session.passport.user
    logger.info 'connections: ' + connectionCount++

    #join user's room
    logger.debug "user #{user} joining socket.io room"
    socket.join user

#    socket.on "control", (data) ->
#      handleControlMessage(user, data)

    socket.on "message", (data) ->
      handleMessage(user, data)


  #delete messages
  app.delete "/messages/:username/before/:id", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, (req, res, next) ->
    messageId = req.params.id
    return next new Error 'id required' unless messageId?

    username = req.user.username
    otherUser = req.params.username
    room = getRoomName username, otherUser


    deleteMyMessagesBeforeId username, otherUser, messageId, true, (err) ->
      return next err if err?
      createAndSendMessageControlMessage username, otherUser, room, "deleteAll", room, messageId, (err) ->
        return next err if err?
        res.send 204


  deleteMyMessagesBeforeId = (username, otherUser, messageId, markTheirsDeleted, callback) ->
    room = getRoomName username, otherUser
    getAllEarlierMessagesInclusiveOf room, messageId, (err, messages) ->
      return callback err if err?
      ourMessageIds = []
      theirMessageIds = []
      async.filter(
        messages
        (item, callback) ->
          oMessage = JSON.parse(item)
          if oMessage.from is username
            ourMessageIds.push oMessage.id
            callback true
          else
            theirMessageIds.push oMessage.id
            callback false
        (results) ->
          multi = rc.multi()
          if ourMessageIds.length > 0
            #zrem does not handle array as last parameter https://github.com/mranney/node_redis/issues/404
            results.unshift "messages:#{room}"
            #need z remove by score here :( http://redis.io/commands/zrem#comment-845220154
            #remove the messages
            multi.zrem results
            #remove deleted message ids from other user's deleted set as the message is gone now
            multi.srem "deleted:#{otherUser}:#{room}", ourMessageIds
          #todo remove the associated control messages

          if theirMessageIds.length > 0 and markTheirsDeleted
            #add their message id's to our deleted message set
            multi.sadd "deleted:#{username}:#{room}", theirMessageIds


          multi.exec (err, mResults) ->
            return callback err if err?
            callback())


  app.delete "/messages/:username/:id", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, (req, res, next) ->

    messageId = req.params.id
    return next new Error 'id required' unless messageId?

    username = req.user.username
    otherUser = req.params.username
    room = getRoomName username, otherUser
    #get the message we're modifying
    getMessage room, messageId, (err, dMessage) ->
      return next err if err?
      return res.send 404 unless dMessage?

      deleteMessage = (callback) ->
        #if we sent it, delete the data
        if (username is dMessage.from)

          #update message data
          removeMessage dMessage.to, room, messageId, (err, count) ->
            return callback err if err?

            #delete the file if it's a file
            if dMessage.mimeType is "image/"
              newPath = __dirname + "/static" + dMessage.data
              fs.unlink(newPath)

            callback()
        else
          rc.sadd "deleted:#{username}:#{room}", messageId, (err, count) ->
            return callback err if err?
            callback()

      deleteMessage (err) ->
        return next err if err?
        createAndSendMessageControlMessage username, otherUser, room, "delete", room, messageId, (err) ->
          return next err if err?
          res.send 204


  app.put "/messages/:username/:id/shareable", ensureAuthenticated, validateUsernameExists, validateAreFriends, (req, res, next) ->
    messageId = req.params.id
    shareable = req.body.shareable
    return next new Error 'id required' unless messageId?
    return next new Error 'shareable required' unless shareable?

    username = req.user.username
    otherUser = req.params.username
    room = getRoomName username, otherUser
    #get the message we're modifying
    getMessage room, messageId, (err, dMessage) ->
      return next err if err?
      return res.send 404 unless dMessage?

      #update message data
      removeMessage dMessage.to, room, messageId, (err, count) ->
        return next err if err?
        dMessage.shareable = shareable is 'true'
        rc.zadd "messages:#{room}", messageId, JSON.stringify(dMessage), (err, addcount) ->
          return next err if err?
          createAndSendMessageControlMessage username, otherUser, room, (if shareable then "shareable" else "notshareable"), room, messageId, (err) ->
            return next err if err?
            res.send 204

  app.post "/images/:fromversion/:username/:toversion", ensureAuthenticated, validateUsernameExists, validateAreFriends, (req, res, next) ->
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
          createAndSendMessage req.user.username, req.params.fromversion, req.params.username, req.params.toversion, req.files.image.name, relUri, "image/", id
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
    isFriend username, otherUser, (err, result) ->
      return res.send 403 if not result

      #req.url = "/images/" + req.params.room + "/" + req.params.id
      #authenticate but use static so we can use http caching
      staticMiddleware req, res, next


  getConversationIds = (username, callback) ->
    rc.smembers "conversations:" + username, (err, conversations) ->
      return callback err if err?
      if (conversations.length > 0)
        conversationsWithId = _.map conversations, (conversation) -> conversation + ":id"
        rc.mget conversationsWithId, (err, ids) ->
          return next err if err?
          conversationIds = []
          _.each conversations, (conversation, i) -> conversationIds.push { conversation: conversation, id: ids[i] }
          callback null, conversationIds
      else
        callback null, null





  #not sure what to do here...sending a GET with body is frowned upon from a REST standpoint
  #sending a get with the client's latest message ids in the querystring doesn't feel right as it leaks data (more easily)
  #so we are left with using a post with body even though nothing is being modified
  app.post "/messageids", ensureAuthenticated, setNoCache, (req, res, next) ->
    messageIds = null
    if req.body?.messageIds?
      logger.debug "/messageids: #{req.body.messageIds}"
      messageIds = JSON.parse(req.body.messageIds)

    #compare latest conversation ids against that which we received and then return new messages for conversations # that have them
    getConversationIds req.user.username, (err, conversationIds) ->
      return next err if err?
      res.send conversationIds

  app.get "/latestids/:userControlId", ensureAuthenticated, setNoCache, (req, res, next) ->
    userControlId = req.params.userControlId
    return next new Error 'no userControlId' unless userControlId?


    getUserControlMessagesAfterId req.user.username, parseInt(userControlId), (err, userControlMessages) ->
      return next err if err?

      data =  {}
      if userControlMessages?.length > 0
        data.userControlMessages = userControlMessages
        logger.debug "/latestids userControlMessages: #{userControlMessages}"
      getConversationIds req.user.username, (err, conversationIds) ->
        return next err if err?

        return res.send data unless conversationIds?
        controlIdKeys = []
        async.each(
          conversationIds
          (item, callback) ->
            controlIdKeys.push "control:message:#{item.conversation}:id"
            callback()
          (err) ->
            return next err if err?
            #Get control ids
            rc.mget controlIdKeys, (err, rControlIds) ->
              return next err if err?
              controlIds = []
              _.each(
                rControlIds
                (controlId, i) ->
                  if controlId isnt null
                    controlIds.push({conversation: conversationIds[i].conversation, id: controlId}))

              if conversationIds.length > 0
                data.conversationIds = conversationIds

              if controlIds.length > 0
                data.controlIds = controlIds
              logger.debug "/latestids sending #{JSON.stringify(data)}"
              res.send data)



            #get last x messages
  app.get "/messages/:username", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, setNoCache, (req, res, next) ->
    #return last x messages
    getMessages req.user.username, getRoomName(req.user.username, req.params.username), 30, (err, data) ->
      #    rc.zrange "messages:" + getRoomName(req.user.username, req.params.remoteuser), -50, -1, (err, data) ->
      return next err if err?
      res.send data

  #get remote messages before id
  app.get "/messages/:username/before/:messageid", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, setNoCache, (req, res, next) ->
    #return messages since id
    getMessagesBeforeId req.user.username, getRoomName(req.user.username, req.params.username), req.params.messageid, (err, data) ->
      return next err if err?
      res.send data

  app.get "/messagedata/:username/:messageid/:controlmessageid", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, setNoCache, (req, res, next) ->
    getMessagesAfterId req.user.username, getRoomName(req.user.username, req.params.username), parseInt(req.params.messageid), (err, messageData) ->
      return next err if err?
      #return messages since id
      getControlMessagesAfterId getRoomName(req.user.username, req.params.username), parseInt(req.params.controlmessageid), (err, controlData) ->
        return next err if err?
        data = {}
        if messageData?
          data.messages = messageData
        if controlData?
          data.controlMessages = controlData

        sData = JSON.stringify(data)
        logger.debug "sending: #{sData}"
        res.send sData

  #app.get "/test", (req, res) ->
  # res.sendfile path.normalize __dirname + "/../assets/html/test.html"

  #app.get "/", (req, res) ->
  # res.sendfile path.normalize __dirname + "/../assets/html/layout.html"

  #todo figure out caching
  app.get "/publickeys/:username", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, setNoCache, getPublicKeys
  app.get "/publickeys/:username/:version", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, setCache(oneYear), getPublicKeys
  app.get "/keyversion/:username", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted,(req, res, next) ->
    rc.get "keyversion:#{req.params.username}", (err, version) ->
      return callback err if err?
      res.send version

  app.get "/users/:username/exists", setNoCache, (req, res, next) ->
    userExists req.params.username, (err, exists) ->
      return next err if err?
      res.send exists

  handleAutoInviteUser = (username, autoInviteUser, callback) ->
      #send invite
      inviteUser username, autoInviteUser, (err, inviteSent) ->
        return callback err if err?
        callback()


  createNewUser = (req, res, next) ->
    username = req.body.username
    password = req.body.password
    logger.debug "/users, username: #{username}, password: #{password}"

    #return next new Error('username required') unless username?
    #return next new Error('password required') unless password?

    userExists username, (err, exists) ->
      return next err if err?
      if exists
        logger.debug "user already exists"
        return res.send 409
      else


        user = {}
        user.username = username

        keys = {}
        if req.body.dhPub?
          keys.dhPub = req.body.dhPub
        else
          return next new Error('dh public key required')

        if req.body.dsaPub?
          keys.dsaPub = req.body.dsaPub
        else
          return next new Error('dsa public key required')

        return next new Error('auth signature required') unless req.body?.authSig?

        if req.body.gcmId?
          user.gcmId = req.body.gcmId

        autoInviteUser = req.body.autoInviteUser

        logger.debug "gcmID: #{user.gcmId}"
        logger.debug "autoInviteUser: #{autoInviteUser}"

        bcrypt.genSalt 10, 32, (err, salt) ->
          return next err if err?
          bcrypt.hash password, salt, (err, password) ->
            return next err if err?
            user.password = password

            #sign the keys
            keys.dhPubSig = crypto.createSign('sha256').update(new Buffer(keys.dhPub)).sign(serverPrivateKey, 'base64')
            keys.dsaPubSig = crypto.createSign('sha256').update(new Buffer(keys.dsaPub)).sign(serverPrivateKey, 'base64')
            logger.debug "#{keys.username}, dhPubSig: #{keys.dhPubSig}, dsaPubSig: #{keys.dsaPubSig}"

            #get key version
            rc.incr "keyversion:#{username}", (err, kv) ->
              return next err if err?
              multi = rc.multi()
              userKey = "users:#{username}"
              keysKey = "keys:#{username}:#{kv}"
              keys.version = kv + ""
              multi.hmset userKey, user
              multi.hmset keysKey, keys
              multi.sadd "users", username
              multi.exec (err,replies) ->
                return next err if err?
                logger.debug "created user: #{username}"
                req.login user, ->
                  req.user = user
                  if autoInviteUser?
                    handleAutoInviteUser username, autoInviteUser, (err) ->
                      return next err if err?
                      next()
                  else
                    next()



  app.post "/users", validateUsernamePassword, createNewUser, passport.authenticate("local"), (req, res, next) ->
    res.send 201

  app.post "/login", passport.authenticate("local"), (req, res, next) ->
    username = req.user.username
    autoInviteUser = req.body.autoInviteUser
    logger.debug "/login post, user #{username}, autoInviteUser: #{autoInviteUser}"

    if autoInviteUser?
      userExists autoInviteUser, (err, exists) ->
        return next err if err?
        if exists
          handleAutoInviteUser username, autoInviteUser, (err) ->
            return next err if err?
            "#{username} auto invited user"
            res.send 204
        else
          res.send 204
    else
      res.send 204

  app.post "/keytoken", setNoCache, (req, res, next) ->
    return res.send 403 unless req.body?.username?
    return res.send 403 unless req.body?.authSig?
    return res.send 403 unless req.body?.password?

    username = req.body.username
    password = req.body.password
    authSig = req.body.authSig
    validateUser username, password, authSig, null, (err, status, user) ->
      return done(err) if err?
      return res.send 403 unless user?

      #the user wants to update their key so we will generate a token that the user signs to make sure they're not using a replay attack of some kind
      #get the current version
      rc.get "keyversion:#{username}", (err, currkv) ->
        return next err if err?

        #inc key version
        kv = parseInt(currkv) + 1
        crypto.randomBytes 32, (err, buf) ->
          return next err if err?
          token = buf.toString('base64')
          rc.set "keytoken:#{username}", token, (err, result) ->
            return next err if err?
            res.send {keyversion: kv, token: token}

  app.post "/keys", (req, res, next) ->
    logger.debug "/keys"
    return res.send 403 unless req.body?.username?
    return res.send 403 unless req.body?.authSig?
    return res.send 403 unless req.body?.password?
    return next new Error('dh public key required') unless req.body?.dhPub?
    return next new Error('dsa public key required') unless req.body?.dsaPub?
    return next new Error 'key version required' unless req.body?.keyVersion?
    return next new Error 'token signature required' unless req.body?.tokenSig?


    #make sure the key versions match
    username = req.body.username

    kv = req.body.keyVersion
    rc.get "keyversion:#{username}", (err, storedkv) ->
      return next err if err?

      storedkv++
      return next new Error 'key versions do not match' unless storedkv is parseInt(kv)

      #todo transaction
      #make sure the tokens match
      rc.get "keytoken:#{username}", (err, rtoken) ->
        newKeys = {}
        newKeys.dhPub = req.body.dhPub
        newKeys.dsaPub = req.body.dsaPub
        logger.debug "received token signature: " + req.body.tokenSig
        logger.debug "received auth signature: " + req.body.authSig
        logger.debug "token: " + rtoken

        password = req.body.password

        #validate the signature against the token

        getLatestKeys username, (err, keys) ->
          return done err if err?
          return done new Error "no keys exist for user #{username}" unless keys?

          #verified = crypto.createVerify('sha256').update(token).update(new Buffer(password)).verify(keys.dsaPub, new Buffer(req.body.tokenSig, 'base64'))

          verified = verifySignature new Buffer(rtoken, 'base64'), new Buffer(password), req.body.tokenSig, keys.dsaPub
          return res.send 403 unless verified

          authSig = req.body.authSig
          validateUser username, password, authSig, null, (err, status, user) ->
            return done(err) if err?
            return res.send 403 unless user?

            #delete the token of which there should only be one
            rc.del "keytoken:#{username}", (err, rdel) ->
              return next err if err?
              return res.send 404 unless rdel is 1

              #sign the keys
              newKeys.dhPubSig = crypto.createSign('sha256').update(new Buffer(newKeys.dhPub)).sign(serverPrivateKey, 'base64')
              newKeys.dsaPubSig = crypto.createSign('sha256').update(new Buffer(newKeys.dsaPub)).sign(serverPrivateKey, 'base64')
              logger.debug "saving keys #{username}, dhPubSig: #{newKeys.dhPubSig}, dsaPubSig: #{newKeys.dsaPubSig}"

              keysKey = "keys:#{username}:#{storedkv}"
              newKeys.version = storedkv + ""
              #add the keys to the key set and add revoke message in transaction
              multi = rc.multi()
              multi.hmset keysKey, newKeys
              #update the version
              multi.set "keyversion:#{username}", storedkv

              #send revoke message
              multi.exec (err, replies) ->
                return next err if err?
                sendRevokeMessages username, storedkv
                res.send 201


  app.post "/validate", (req, res, next) ->
    username = req.body.username
    password = req.body.password
    authSig = req.body.authSig

    validateUser username, password, authSig, null, (err, status, user) ->
      return next err if err?
      res.send status

  app.post "/registergcm", ensureAuthenticated, (req, res, next) ->
    gcmId = req.body.gcmId
    userKey = "users:" + req.user.username
    rc.hset userKey, "gcmId", gcmId, (err) ->
      return next err if err?
      res.send 204


  inviteUser = (username, friendname, callback) ->
    multi = rc.multi()
    #remove you from my blocked set if you're blocked
    multi.srem "blocked:#{username}", friendname
    multi.sadd "invited:#{username}", friendname
    multi.sadd "invites:#{friendname}", username
    multi.exec (err, results) ->
      return callback err if err?
      invitesCount = results[2]
      #send to room
      if invitesCount > 0
        createAndSendUserControlMessage username, "invited", friendname, null, (err) ->
          return callback err if err?
          createAndSendUserControlMessage friendname, "invite", username, null, (err) ->
            return callback err if err?
            #sio.sockets.in(friendname).emit "notification", {type: 'invite', data: username}
            #send gcm message
            userKey = "users:" + friendname
            rc.hget userKey, "gcmId", (err, gcmId) ->
              if err?
                logger.error ("ERROR: " + err)
                return callback new Error err

              if gcmId?.length > 0
                logger.debug "sending gcm notification"
                gcmmessage = new gcm.Message()
                sender = new gcm.Sender("#{googleApiKey}")
                gcmmessage.addData "type", "invite"
                gcmmessage.addData "sentfrom", username
                gcmmessage.addData "to", friendname
                gcmmessage.delayWhileIdle = true
                gcmmessage.timeToLive = 3
                gcmmessage.collapseKey = "invite:#{friendname}"
                regIds = [gcmId]

                sender.send gcmmessage, regIds, 4, (result) ->
                  #logger.debug(result)
                  callback null, true
              else
                logger.debug "gcmId not set for #{friendname}"
                callback null, true
      else
        callback null, false

  app.post "/invite/:username", ensureAuthenticated, validateUsernameExists, (req, res, next) ->
    friendname = req.params.username
    username = req.user.username

    # the caller wants to add himself as a friend
    if friendname is username then return res.send 403

    logger.debug "#{username} inviting #{friendname} to be friends"
    #check if friendname has blocked username
    rc.sismember "blocked:#{friendname}", username, (err, blocked) ->
      return res.send 404 if blocked

      #see if they are already friends
      isFriend username, friendname, (err, result) ->
        #if they are, do nothing
        if result then res.send 409
        else
          #see if there's already an invite and if so accept automatically
          inviteExists friendname, username, (err, invited) ->
            return next err if err?
            if invited
              deleteInvites username, friendname, (err) ->
                return next err if err?
                createFriendShip username, friendname, (err) ->
                  return next err if err?

                  createAndSendUserControlMessage username, "accept", friendname, null, (err) ->
                    return next err if err?
                    sendInviteResponseGcm username, friendname, 'accept', (result) ->
                      createAndSendUserControlMessage friendname, "accept", username, null, (err) ->
                        return next err if err?
                        #sio.sockets.to(friendname).emit "inviteResponse", JSON.stringify { user: username, response: 'accept' }
                        #sio.sockets.to(username).emit "inviteResponse", JSON.stringify { user: friendname, response: 'accept' }
                        sendInviteResponseGcm friendname, username, 'accept', (result) ->
                          res.send 204
            else
              inviteUser username, friendname, (err, inviteSent) ->
                res.send if inviteSent then 204 else 403

  createFriendShip = (username, friendname, callback) ->
    multi = rc.multi()
    multi.sadd "friends:#{username}", friendname
    multi.sadd "friends:#{friendname}", username
    multi.srem "users:deleted:#{username}", friendname
    multi.srem "users:deleted:#{friendname}", username
    multi.exec (err, results) ->
      callback next new Error("[friend] sadd failed for username: " + username + ", friendname" + friendname) if err?
      createAndSendUserControlMessage username, "added", friendname, null, (err) ->
        return callback err if err?
        createAndSendUserControlMessage friendname, "added", username, null, (err) ->
          return callback err if err?
          callback null

  deleteInvites = (username, friendname, callback) ->
    multi = rc.multi()
    multi.srem "invited:#{friendname}", username
    multi.srem "invites:#{username}", friendname
    multi.exec (err, results) ->
      callback new Error("[friend] srem failed for invites:#{username}:#{friendname}") if err?
      callback null

  sendInviteResponseGcm = (username, friendname, action, callback) ->
    userKey = "users:" + friendname
    rc.hget userKey, "gcmId", (err, gcmId) ->
      if err?
        logger.error ("ERROR: " + err)
        return next new Error err

      if gcmId?.length > 0
        logger.debug "sending gcm invite response notification"

        gcmmessage = new gcm.Message()
        sender = new gcm.Sender("#{googleApiKey}")
        gcmmessage.addData("type", "inviteResponse")
        gcmmessage.addData "sentfrom", username
        gcmmessage.addData "to", friendname
        gcmmessage.addData("response", action)
        gcmmessage.delayWhileIdle = true
        gcmmessage.timeToLive = 3
        gcmmessage.collapseKey = "inviteResponse:#{friendname}"
        regIds = [gcmId]

        sender.send gcmmessage, regIds, 4, (result) ->
          callback result
      else
          callback null

  app.post '/invites/:username/:action', ensureAuthenticated, validateUsernameExists, (req, res, next) ->
    return next new Error 'action required' unless req.params.action?

    logger.debug 'POST /invites'
    username = req.user.username
    friendname = req.params.username

    #make sure invite exists
    inviteExists friendname, username, (err, result) ->
      return next err if err?
      return res.send 404 if not result
      action = req.params.action
      deleteInvites username, friendname, (err) ->
        return next err if err?
        switch action
          when 'accept'
            createFriendShip username, friendname, (err) ->
              return next err if err?
              sendInviteResponseGcm username, friendname, action, (result) ->
                res.send 204
          when 'ignore'
            createAndSendUserControlMessage friendname, 'ignore', username, null, (err) ->
              return next err if err?
              res.send 204

          when 'block'
            rc.sadd "blocked:#{username}", friendname, (err, data) ->
              return next err if err?
              createAndSendUserControlMessage friendname, 'ignore', username, null, (err) ->
                return next err if err?
                res.send 204

          else return next new Error 'invalid action'


  getFriends = (req, res, next) ->
    username = req.user.username
    #get users we're friends with
    rc.smembers "friends:#{username}", (err, rfriends) ->
      return next err if err?
      friends = {}
      return res.send {} unless rfriends?

      _.each rfriends, (name) -> friends[name] = 0

      #get users that invited us
      rc.smembers "invites:#{username}", (err, invites) ->
        return next err if err?
        _.each invites, (name) -> friends[name] = 32

        #get users that we invited
        rc.smembers "invited:#{username}", (err, invited) ->
          return next err if err?
          _.each invited, (name) -> friends[name] = 2

          #get users that deleted us that we haven't deleted
          rc.smembers "users:deleted:#{username}", (err, deleted) ->
            return next err if err?
            _.each deleted, (name) ->
              if not friends[name]?
                friends[name] = 1
              else
                friends[name] += 1

            rc.get "control:user:#{username}:id", (err, id) ->
              friendstate = {}
              friendstate.userControlId = id ? 0
              friendstate.friends = friends

              sFriendState = JSON.stringify friendstate
              logger.debug ("friendstate: " + sFriendState)
              res.send sFriendState

  app.get "/friends", ensureAuthenticated, setNoCache, getFriends

  app.delete "/friends/:username", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeletedOrInvited, (req, res, next) ->
    username = req.user.username
    theirUsername = req.params.username
    room = getRoomName username, theirUsername




    #if i invited him

    rc.sismember "invited:#{username}", theirUsername, (err, isInvited) ->
      return next err if err?
      if isInvited
        deleteInvites theirUsername, username, (err) ->
          return next err if err?

          #if all we've done is invite them
          createAndSendUserControlMessage username, "rescind", theirUsername, null, (err) ->
            return next err if err?
            #tell them we've been deleted
            createAndSendUserControlMessage theirUsername, "rescind", username, null, (err) ->
              return next err if err?
              res.send 204
      else
        multi = rc.multi()

        #delete the set that held message ids of theirs that we deleted
        multi.del "deleted:#{username}:#{room}"

        #delete the conversation with this user from the set of my conversations
        multi.srem "conversations:#{username}", room

        #todo delete related user control messages

        #if i've been deleted by them this will be populated with their username
        rc.sismember "users:deleted:#{username}", theirUsername, (err, theyHaveDeletedMe) ->
          return next err if err?

          #if we are deleting them and they haven't deleted us already
          if not theyHaveDeletedMe
            #delete our messages with the other user
            rc.get "#{room}:id", (err, id) ->

              deleteMessages = (messageId, callback) ->
                if messageId?
                  deleteMyMessagesBeforeId username, theirUsername, messageId, false, (err) ->
                    callback err if err?
                    callback()
                else
                  callback()

              deleteMessages id, (err) ->
                return next err if err?
                #delete friend association
                multi.srem "friends:#{username}", theirUsername
                multi.srem "friends:#{theirUsername}", username

                #add me to their set of deleted users
                multi.sadd "users:deleted:#{theirUsername}", username
                multi.exec (err, results) ->
                  return next err if err?
                  #tell (todo) other connections logged in as us that we deleted someone
                  createAndSendUserControlMessage username, "delete", theirUsername, username, (err) ->
                    return next err if err?
                    #tell them we've been deleted
                    createAndSendUserControlMessage theirUsername, "delete", username, username, (err) ->
                      return next err if err?
                      res.send 204

          #they've already deleted me
          else
            #delete control message data
            multi.del "control:message:#{room}"
            multi.del "control:message:#{room}:id"

            #remove them from deleted set
            multi.srem "users:deleted:#{username}", theirUsername

            #delete message data
            multi.del "#{room}:id"
            multi.del "messages:#{room}"

            multi.exec (err, results) ->
              return next err if err?

              #tell (todo) other connections logged in as us that we deleted someone
              createAndSendUserControlMessage username, "delete", theirUsername, username, (err) ->
                return next err if err?
                res.send 204


  app.post "/logout", ensureAuthenticated, (req, res) ->
    req.logout()
    res.send 204


  comparePassword = (password, dbpassword, callback) ->
    bcrypt.compare password, dbpassword, callback

  getLatestKeys = (username, callback) ->
    rc.get "keyversion:#{username}", (err, version) ->
      return callback err if err?
      return callback new Error 'no keys exist for user: #{username}' unless version?

      rc.hgetall "keys:#{username}:#{version}", (err, keys) ->
        return callback err if err?
        callback null, keys

  verifySignature = (b1, b2, sigString, pubKey) ->
    #get the signature
    buffer = new Buffer(sigString, 'base64')

    #random is stored in first 16 bytes
    random = buffer.slice 0, 16
    signature = buffer.slice 16

    return crypto.createVerify('sha256').update(b1).update(b2).update(random).verify(pubKey, signature)


  validateUser = (username, password, signature, gcmId, done) ->
    return done(null, 403) if (!checkUser(username) or !checkPassword(password))
    return done(null, 403) if signature.length < 16
    userKey = "users:" + username
    logger.debug "validating: " + username
    rcs.hgetall userKey, (err, user) ->
      return done(err) if err?
      return done null, 404 if not user
      comparePassword password, user.password, (err, res) ->
        return done err if err?
        return done null, 403 if not res

        #not really worried about replay attacks here as we're using ssl but as extra security the server could send a challenge that the client would sign as we do with key roll
        getLatestKeys username, (err, keys) ->
          return done err if err?
          return done new Error "no keys exist for user #{username}" unless keys?

          verified = verifySignature new Buffer(username), new Buffer(password), signature, keys.dsaPub

          #crypto.createVerify('sha256').update(new Buffer(username)).update(new Buffer(password)).update(random).verify(keys.dsaPub, signature)
          logger.debug "validated, #{username}: #{verified}"

          #update the gcm if we were sent one and it's different and we're verified
          if gcmId? and user.gcmId isnt gcmId and verified
            rc.hset userKey, 'gcmId', gcmId

          status = if verified then 204 else 403
          done null, status, if verified then user else null


  passport.use new LocalStrategy ({passReqToCallback: true}), (req, username, password, done) ->
    signature = req.body.authSig
    validateUser username, password, signature, req.body.gcmId, (err, status, user) ->
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

