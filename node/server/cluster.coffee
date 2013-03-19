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
_ = require 'underscore'

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

  createAndSendUserControlMessage = (user, action, data, moredata, callback) ->
    message = {}
    message.type = "user"
    message.action = action
    message.data = data

    if moredata?
      message.moredata = moredata

    #send control message to ourselves
    getNextUserControlId user,(id) ->
      return callback new Error 'could not get user control id' unless id?
      message.id = id
      newMessage = JSON.stringify(message)
      #store messages in sorted sets
      rc.zadd "control:user:#{user}", id, newMessage, (err, addcount) ->
        #end transaction here
        return callback err if err?
        sio.sockets.to(user).emit "control", newMessage
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




  handleControlMessage = (username, data) ->
    logger.debug "received control message: #{data}"
    message = JSON.parse(data)

    # message.user = user
    return unless message.from is username

    type = message.type
    return unless type?
    action = message.action
    return unless action?
    localid = message.localid
    return unless localid?
    room = message.data
    return unless room?
    messageId = message.moredata
    return unless messageId?
    resendId = message.resendId

    #make sure we're a member of this conversation
    hasConversation username, room, (err, result) ->
      return next err if err?
      return if not result
      otherUser = getOtherUser room, username

      #check for dupes if message has been resent
      checkForDuplicateControlMessage resendId, room, message, (err, found) ->
        if found
          logger.debug "found duplicate control message, not adding to db"
          if (action is 'delete')
            #if it's delete, broadcast
            sio.sockets.to(username).emit "control", found
            sio.sockets.to(otherUser).emit "control", found

        else
          #get the message we're modifying
          getMessage room, messageId, (err, dMessage) ->
            return if err?
            return unless dMessage?
            if action is "delete"
              #if we sent it, delete the data
              if (username is dMessage.from)
                #update message data
                removeMessage dMessage.to, room, messageId, (err, count) ->
                  return err if err?

                         #delete the file if it's a file
                  if dMessage.mimeType is "image/"
                    newPath = __dirname + "/static" + dMessage.data
                    fs.unlink(newPath)

#                  dMessage.deletedFrom = true
#                  dMessage.deletedTo = true
#                  delete dMessage.data
#                  delete dMessage.datetime
              else
                rc.sadd "deleted:#{username}:#{room}", messageId, (err, count) ->
                  return err if err?

              #add control message
              getNextMessageControlId room, (id) ->
                return unless id?
                message.id = id
                message.from = username
                sMessage = JSON.stringify message
                rc.zadd "control:message:#{room}", id, sMessage, (err, addcount) ->
                  return err if err?
                  sio.sockets.to(username).emit "control", sMessage

                  #if it's our message, tell the other user; if it's their message they don't care wtf we did
                  if dMessage.from is username
                    sio.sockets.to(otherUser).emit "control", sMessage

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
        #if they're not friends disconnect them, wtf are they trying to do here?
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

    socket.on "control", (data) ->
      handleControlMessage(user, data)

    socket.on "message", (data) ->
      handleMessage(user, data)



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




  #not sure what to do here...sending a GET with body is frowned upon from a REST standpoint
  #sending a get with the client's latest message ids in the querystring doesn't feel right as it leaks data (more easily)
  #so we are left with using a post with body even though nothing is being modified..roy?
#  app.post "/messages", ensureAuthenticated, setNoCache, (req, res, next) ->
#    messageIds = null
#    if req.body?.messageIds?
#      logger.debug "/messages, messageIds:#{req.body.messageIds}"
#      messageIds = JSON.parse(req.body.messageIds)
#
#    #compare latest conversation ids against that which we received and then return new messages for conversations # that have them
#    getConversationIds req.user.username, (err, conversationIds) ->
#      return res.send '[]' unless conversationIds?
#      allMessages = []
#      async.each(
#        conversationIds
#        (item, callback) ->
#          conversation = item.conversation
#          clientId = null
#          if messageIds?
#            clientId = messageIds[conversation]
#          if clientId?
#            delta = item.id - clientId
#            if delta is 0
#              logger.debug "/messages, conversation:#{conversation}, delta nought"
#              callback()
#            else
#              getMessagesAfterId(conversation, clientId, (err, messages) ->
#                return callback err if err?
#                allMessages.push { spot: conversation, messages: messages }
#                callback())
#          else
#            getMessages(conversation, 30, (err, messages) ->
#              return callback err if err?
#              allMessages.push {spot: conversation, messages: messages}
#              callback())
#        (err) ->
#          return next err if err?
#          logger.debug "/messages sending #{JSON.stringify(allMessages)}"
#          res.send allMessages)




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
  app.get "/messages/:username", ensureAuthenticated, validateUsernameExists, validateAreFriends, setNoCache, (req, res, next) ->
    #return last x messages
    getMessages req.user.username, getRoomName(req.user.username, req.params.username), 30, (err, data) ->
      #    rc.zrange "messages:" + getRoomName(req.user.username, req.params.remoteuser), -50, -1, (err, data) ->
      return next err if err?
      res.send data


  #get remote messages since id
#  app.get "/messages/:username/after/:messageid", ensureAuthenticated, validateUsernameExists, validateAreFriends, setNoCache, (req, res, next) ->
#    #return messages since id
#    getMessagesAfterId getRoomName(req.user.username, req.params.username), req.params.messageid, (err, data) ->
#      return next err if err?
#      res.send data

  #get remote messages before id
  app.get "/messages/:username/before/:messageid", ensureAuthenticated, validateUsernameExists, validateAreFriends, setNoCache, (req, res, next) ->
    #return messages since id
    getMessagesBeforeId req.user.username, getRoomName(req.user.username, req.params.username), req.params.messageid, (err, data) ->
      return next err if err?
      res.send data


#  app.get "/controlmessages/:username/after/:controlmessageid", ensureAuthenticated, validateUsernameExists, validateAreFriends, setNoCache, (req, res, next) ->
#    #return messages since id
#    getControlMessagesAfterId getRoomName(req.user.username, req.params.username), req.params.controlmessageid, (err, data) ->
#      return next err if err?
#      res.send data

  app.get "/messagedata/:username/:messageid/:controlmessageid", ensureAuthenticated, validateUsernameExists, validateAreFriends, setNoCache, (req, res, next) ->
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

#  app.get "/usercontrol/:controlmessageid", ensureAuthenticated, setNoCache, (req, res, next) ->
#    getUserControlMessagesAfterId req.user.username, parseInt(req.params.controlmessageid), (err, data) ->
#      return next err if err?
#      res.send JSON.stringify(data)


  #app.get "/test", (req, res) ->
  # res.sendfile path.normalize __dirname + "/../assets/html/test.html"

  #app.get "/", (req, res) ->
  # res.sendfile path.normalize __dirname + "/../assets/html/layout.html"

  #todo figure out caching
  app.get "/publickeys/:username", ensureAuthenticated, validateUsernameExists, validateAreFriends, setNoCache, getPublicKeys
  app.get "/publickeys/:username/:version", ensureAuthenticated, validateUsernameExists, validateAreFriends, setCache(oneYear), getPublicKeys
  app.get "/keyversion/:username", ensureAuthenticated, validateUsernameExists, validateAreFriends,(req, res, next) ->
    rc.get "keyversion:#{req.params.username}", (err, version) ->
      return callback err if err?
      res.send version

  app.get "/users/:username/exists", setNoCache, (req, res, next) ->
    userExists req.params.username, (err, exists) ->
      return next err if err?
      res.send exists


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

        logger.debug "gcmID: #{user.gcmId}"

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
                  next()


  app.post "/users", validateUsernamePassword, createNewUser, passport.authenticate("local"), (req, res, next) ->
    res.send 201

  app.post "/login", passport.authenticate("local"), (req, res, next) ->
    logger.debug "/login post"
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

  app.post "/invite/:username", ensureAuthenticated, validateUsernameExists, (req, res, next) ->
    friendname = req.params.username
    username = req.user.username

    # the caller wants to add himself as a friend
    if friendname is username then return res.send 403

    logger.debug "#{username} inviting #{friendname} to be friends"
    #todo check if friendname has ignored username
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
            #todo use transaction
            #add to the user's set of people he's invited
            rc.sadd "invited:#{username}", friendname, (err, invitedCount) ->
              next new Error("Could not set invited") if err

              rc.sadd "invites:#{friendname}", username, (err, invitesCount) ->
                next new Error("Could not set invites") if err

                #send to room
                #todo push notification
                if invitesCount > 0
                  createAndSendUserControlMessage username, "invited", friendname, null, (err) ->
                    return next err if err?
                    createAndSendUserControlMessage friendname, "invite", username, null, (err) ->
                      return next err if err?
                      #sio.sockets.in(friendname).emit "notification", {type: 'invite', data: username}
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

  createFriendShip = (username, friendname, callback) ->
    rc.sadd "friends:#{username}", friendname, (err, data) ->
      callback next new Error("[friend] sadd failed for username: " + username + ", friendname" + friendname) if err?
      rc.sadd "friends:#{friendname}", username, (err, data) ->
        callback next new Error("[friend] sadd failed for username: " + username + ", friendname" + friendname) if err?
        createAndSendUserControlMessage username, "added", friendname, null, (err) ->
          return callback err if err?
          createAndSendUserControlMessage friendname, "added", username, null, (err) ->
            return callback err if err?
            callback null




  deleteInvites = (username, friendname, callback) ->
    rc.srem "invited:#{friendname}", username, (err, data) ->
      callback new Error("[friend] srem failed for invited:#{friendname}:#{username}") if err?
      rc.srem "invites:#{username}", friendname, (err, data) ->
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
        sender = new gcm.Sender("AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ")
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

  app.post '/invites/:username/:action', ensureAuthenticated, (req, res, next) ->
    logger.debug 'POST /invites'
    username = req.user.username
    friendname = req.params.username

    #make sure invite exists
    inviteExists friendname, username, (err, result) ->
      return next err if err?
      return res.send 404 if not result
      accept = req.params.action is 'accept'
      deleteInvites username, friendname, (err) ->
        return next err if err?
        if accept
          createFriendShip username, friendname, (err) ->
            return next err if err?
            #sio.sockets.to(friendname).emit "inviteResponse", JSON.stringify { user: username, response: req.params.action }
            sendInviteResponseGcm username, friendname, req.params.action, (result) ->
              res.send 204
        else
          rc.sadd "ignores:#{username}", friendname, (err, data) ->
            return next new Error("[friend] sadd failed for username: " + username + ", friendname" + friendname) if err?
            createAndSendUserControlMessage friendname, "decline", username, null, (err) ->
              #sio.sockets.to(friendname).emit "inviteResponse", JSON.stringify { user: username, response: req.params.action }
              res.send 204


  getFriends = (req, res, next) ->
    username = req.user.username
    rc.smembers "friends:#{username}", (err, rfriends) ->
      return next err if err?
      friends = []
      return res.send {} unless rfriends?

      _.each rfriends, (name) -> friends.push {name: name}

      rc.smembers "invites:#{username}", (err, invites) ->
        return next err if err?
        _.each invites, (name) -> friends.push {flags: 32, name: name}

        rc.smembers "invited:#{username}", (err, invited) ->
          return next err if err?
          _.each invited, (name) -> friends.push {flags: 2, name: name}


          rc.get "control:user:#{username}:id", (err, id) ->
            friendstate = {}
            friendstate.userControlId = id ? 0
            friendstate.friends = friends

            sFriendState = JSON.stringify friendstate
            logger.debug ("friendstate: " + sFriendState)
            res.send sFriendState

  app.get "/friends", ensureAuthenticated, setNoCache, getFriends


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

