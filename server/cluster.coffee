cluster = require('cluster')
https = require('https')
numCPUs = require('os').cpus().length
cookie = require("cookie")
express = require("express")
passport = require("passport")
LocalStrategy = require("passport-local").Strategy
crypto = require 'crypto'
RedisStore = require("connect-redis")(express)
util = require("util")
gcm = require("node-gcm")
fs = require("fs")
bcrypt = require 'bcrypt'
mkdirp = require("mkdirp")
expressWinston = require "express-winston"
logger = require("winston")
async = require 'async'
_ = require 'underscore'
querystring = require 'querystring'
formidable = require 'formidable'
#request = require 'request'
#pkgcloud = require 'pkgcloud'
utils = require('connect/lib/utils')
pause = require 'pause'
stream = require 'readable-stream'
cloudfiles = require 'cloudfiles'


MESSAGES_PER_USER = 100
USERNAME_LENGTH = 20


logger.remove logger.transports.Console
logger.setLevels logger.config.syslog.levels
logger.exitOnError = false

transports = []
transports.push new (logger.transports.File)({ dirname: 'logs', filename: 'server.log', maxsize: 1024576, maxFiles: 20, json: false, level: 'debug', handleExceptions: true })
#always use file transport
logger.add transports[0], null, true

database = process.env.NODE_DB ? 0
socketPort = process.env.SOCKET ? 443
env = process.env.NODE_ENV ? 'Local' # one of "Local","Stage", "Prod"

if env is 'Local'
  transports.push new (logger.transports.Console)({colorize: true, timestamp: true, level: 'debug', handleExceptions: true })
  logger.add transports[1], null, true
  numCPUs = 1

logger.debug "__dirname: #{__dirname}"

if (cluster.isMaster && env isnt 'Local')
  # Fork workers.
  for i in [0..1 - numCPUs]
    cluster.fork();

  cluster.on 'online', (worker, code, signal) ->
    logger.debug 'worker ' + worker.process.pid + ' online'

  cluster.on 'exit', (worker, code, signal) ->
    logger.debug 'worker ' + worker.process.pid + ' died'

else
  logger.info "env: #{env}"
  logger.info "database: #{database}"
  logger.info "socket: #{socketPort}"

  #process.on "uncaughtException", uncaught = (err) ->
   # logger.error "Uncaught Exception: " + err

  sio = undefined
  sessionStore = undefined
  rc = undefined
  rcs = undefined
  pub = undefined
  sub = undefined
  client = undefined
  app = undefined
  ssloptions = undefined

  googleApiKey = 'AIzaSyC-JDOca03zSKnN-_YsgOZOS5uBFiDCLtQ'
  rackspaceApiKey = "6c20021990a1fd28f0afa8f0c793599a"
  rackspaceCdnBaseUrlLocal = "https://19be2df346b051f6d1c9-bc27bdc385cad6381ae24d242305422a.ssl.cf1.rackcdn.com"
  rackspaceCdnBaseUrlStage = "https://b8bd94a94939231436ca-1a5c42003e29f66e4992dc05d6c9ef5c.ssl.cf1.rackcdn.com"
  rackspaceCdnBaseUrlProd =  "https://92e4d74ce2d4cdc1c4aa-5c12bd92c930cddf5a9d06a5e7413967.ssl.cf1.rackcdn.com"

  rackspaceCdnBaseUrl = eval("rackspaceCdnBaseUrl#{env}") + ":443"
  rackspaceImageContainer = "surespotImages#{env}"
  #rackspace = pkgcloud.storage.createClient {provider: 'rackspace', username: 'adam2fours', apiKey: rackspaceApiKey}
  cfClient = cloudfiles.createClient {auth: { username: 'adam2fours', apiKey: rackspaceApiKey}}



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



  ssloptions = {
  key: fs.readFileSync("ssl#{env}/surespot.key"),
  cert: fs.readFileSync("ssl#{env}/surespot.crt")
  }

  peerCertPath = "ssl#{env}/PositiveSSLCA2.crt"
  if fs.existsSync(peerCertPath)
    ssloptions["ca"] = fs.readFileSync(peerCertPath)

  serverPrivateKey = fs.readFileSync("ec#{env}/priv.pem")
  sessionSecret = "your mama"

  # create EC keys like so
  # priv key
  # openssl ecparam -name secp521r1 -outform PEM -out priv.pem -genkey
  # pub key
  # openssl ec -inform PEM  -outform PEM -in priv.pem -out pub.pem -pubout
  #
  # verify signature like so
  # openssl dgst -sha256 -verify key -signature sig.bin data


  app = express()
  app.configure ->
    sessionStore = new RedisStore({db: database})
    createRedisClient ((err, c) -> rc = c), database
    createRedisClient ((err, c) -> rcs = c), database
    createRedisClient ((err, c) -> pub = c), database
    createRedisClient ((err, c) -> sub = c), database
    createRedisClient ((err, c) -> client = c), database

    app.use express.compress()
    app.use express.cookieParser()
    app.use express.json()
    app.use express.urlencoded()

    app.use express.session(
      secret: sessionSecret
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

    app.use (err, req, res, next) ->
      res.send err.status or 500

  oneYear = 31536000000

  https.globalAgent.maxSockets = Infinity;

  server = https.createServer ssloptions, app
  server.listen socketPort
  sio = require("socket.io").listen server


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
      req.sessionID = utils.parseSignedCookie(parsedCookie["connect.sid"], sessionSecret)
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
    rc.sismember "users", username, (err, isMember) ->
      return fn err if err?
      return fn null, if isMember then true else false


  userExistsOrDeleted = (username, fn) ->
    rc.sismember "users", username, (err, isMember) ->
      return fn err if err?
      return fn null, true if isMember
      rc.sismember "deleted", username, (err, isMember) ->
        return fn err if err?
        return fn null, true if isMember
        fn null, false


  checkUser = (username) ->
    return username?.length > 0 and username?.length  <= USERNAME_LENGTH


  checkPassword = (password) ->
    return password?.length > 0 and password?.length  <= 2048


  validateUsernamePassword = (req, res, next) ->
    username = req.body.username
    password = req.body.password

    if !checkUser(username) or !checkPassword(password)
      res.send 400
    else
      next()

  validateUsernameExists = (req, res, next) ->
    #pause and resume events - https://github.com/felixge/node-formidable/issues/213
    paused = pause req
    userExistsOrDeleted req.params.username, (err, exists) ->
      if err?
        paused.resume()
        return next err


      if not exists
        paused.resume()
        return res.send 404


      next()
      paused.resume()



  validateAreFriends = (req, res, next) ->
    #pause and resume events - https://github.com/felixge/node-formidable/issues/213
    paused = pause req
    username = req.user.username
    friendname = req.params.username
    isFriend username, friendname, (err, result) ->
      if err?
        paused.resume()
        return next err

      if result

        next()
        paused.resume()
      else
        paused.resume()
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
      getKeys username, version, (err, keys) ->
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
        message = undefined
        try
          message = JSON.parse(data[0])
        catch error
          return fn error

        fn null,message
      else
        fn null, null



  removeRoomMessage = (room, id, fn) ->
    #remove message data from set of room messages
    rc.zremrangebyscore "messages:" + room, id, id, fn

  removeMessage = (to, room, id, fn) ->
    user = getOtherUser room, to

    multi = rc.multi()
    #remove message data from set of room messages
    multi.zremrangebyscore "messages:" + room, id, id

    #remove from other user's deleted messages set
    multi.srem "deleted:#{to}:#{room}", id

    #remove from my total message pointer set
    multi.zrem "messages:#{user}", "messages:#{room}:#{id}"

    multi.exec fn

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

  getAllMessages = (room, fn) ->
    rc.zrange "messages:#{room}", 0, -1, fn


  getMessages = (username, room, count, fn) ->
    #return last x messages
    #args = []
    rc.zrange "messages:#{room}", -count, -1, 'withscores', (err, data) ->
      return fn err if err?
      filterDeletedMessages username, room, data, fn

  getControlMessages = (room, count, fn) ->
    rc.zrange "control:message:" + room, -count, -1, fn

  getUserControlMessages = (user, count, fn) ->
    rc.zrange "control:user:" + user, -count, -1, fn

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
            checkMessage = undefined
            try
              checkMessage = JSON.parse(checkMessageJSON)
            catch error
              return callback error

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
            try
              checkMessage = JSON.parse(checkMessageJSON)
            catch error
              return callback error

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
        rc.zrangebyscore "control:message:" + room, "(" + id, "+inf", fn

  getUserControlMessagesAfterId = (user, id, fn) ->
    if id is -1
      fn null, null
    else
      if id is 0
        getUserControlMessages user, 20, fn
      else
        rc.zrangebyscore "control:user:" + user, "(" + id, "+inf", fn


  checkForDuplicateControlMessage = (resendId, room, message, callback) ->
    if (resendId?)
      logger.debug "searching room: #{room} from id: #{resendId} for duplicate control messages"
      #check messages client doesn't have for dupes
      getControlMessagesAfterId room, resendId, (err, data) ->
        return callback err if err
        found = _.find data, (checkMessageJSON) ->
          checkMessage = undefined
          try
            checkMessage = JSON.parse(checkMessageJSON)
          catch error
            return callback error

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


  MessageError = (id, status) ->
    messageError = {}
    messageError.id = id
    messageError.status = status
    return messageError

  Friend = (name, flags, imageUrl, imageVersion, imageIv) ->
    friend = {}
    friend.name = name
    friend.flags = flags
    if imageUrl?
      friend.imageUrl = imageUrl

    if imageVersion?
      friend.imageVersion = imageVersion

    if imageIv?
      friend.imageIv = imageIv
    return friend


  createAndSendMessage = (from, fromVersion, to, toVersion, iv, data, mimeType, id, callback) ->
    logger.debug "new message"
    time = Date.now()

    message = {}
    message.to = to
    message.from = from
    message.datetime = time
    message.toVersion = toVersion
    message.fromVersion = fromVersion
    message.iv = iv
    message.data = data
    message.mimeType = mimeType
    room = getRoomName(from,to)


    #INCR message id
    getNextMessageId room, id, (id) ->
      return callback new MessageError(iv, 500) unless id?
      message.id = id

      logger.debug "sending message, id:  #{id}, iv: #{iv}, data: #{data}, to user: #{to}"
      newMessage = JSON.stringify(message)

      #store messages in sorted sets
      multi = rc.multi()
      userMessagesKey = "messages:#{from}"
      multi.zadd "messages:#{room}", id, newMessage
      #keep track of all the users message so we can remove the earliest when we cross their threshold
      multi.zadd userMessagesKey, time, "messages:#{room}:#{id}"
      multi.exec  (err, results) ->
        if err?
          logger.error ("ERROR: Socket.io onmessage, " + err)
          return callback new MessageError(iv, 500)


        deleteEarliestMessage = (callback) ->
          #check how many messages the user has total
          rc.zcard userMessagesKey, (err, card) ->
            return callback err if err?
            #TODO per user threshold based on pay status
            #delete the oldest message
            deleteCount = card - MESSAGES_PER_USER

            if deleteCount > 0

              rc.zrange userMessagesKey,  0, deleteCount, (err, messagePointer) ->
                return callback err if err?
                #delete message
                messageData = getMessagePointerData from, messagePointer[0]
                deleteMessage from, messageData.to, messageData.id, true, callback
            else
              callback()

        deleteEarliestMessage (err) ->
          return callback err if err?

          sendGcm = (gcmCallback) ->
            #send gcm message
            userKey = "users:" + to
            rc.hget userKey, "gcmId", (err, gcm_id) ->
              if err?
                logger.error ("ERROR: Socket.io onmessage, " + err)
                gcmCallback(err)

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
                  gcmCallback()
              else
                logger.debug "no gcm id for #{to}"
                gcmCallback()


          sendGcm (err) ->
            return callback new MessageError(iv, 500) if err?

            createConversations = (ccCallback) ->
              if id is 1
                #if this is the first message, add the "room" to the user's list of rooms
                multi = rc.multi()
                multi.sadd "conversations:" + from, room
                multi.sadd "conversations:" + to, room
                multi.exec (err, results) ->
                  return ccCallback err if err?
                  ccCallback()
              else
                ccCallback()

            createConversations (err) ->
              if err?
                logger.error ("ERROR: Socket.io onmessage, " + err)
                return callback new MessageError(iv, 500)

              sio.sockets.to(to).emit "message", newMessage
              sio.sockets.to(from).emit "message", newMessage

              callback()


  getMessagePointerData = (from, messagePointer) ->
    #delete message
    messageData = messagePointer.split(":")
    data = {}
    data.id =  messageData[3]
    room =  messageData[1] + ":" + messageData[2]
    data.to = getOtherUser room, from
    return data


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
    userExists to, (err, exists) ->
      return callback null unless exists
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


  handleMessage = (user, data, callback) ->
    #user = socket.handshake.session.passport.user

    message = undefined
    #todo check from and to exist and are friends
    try
      message = JSON.parse(data)
    catch error
      return callback new MessageError(data, 500)


    # message.user = user
    logger.debug "received message from user #{user}"

    iv = message.iv
    return callback new MessageError(data, 400) unless iv?
    to = message.to
    return callback new MessageError(iv, 400) unless to?
    from = message.from
    return callback new MessageError(iv, 400) unless from?
    toVersion = message.toVersion
    return callback new MessageError(iv, 400) unless toVersion?
    fromVersion = message.fromVersion
    return callback new MessageError(iv, 400) unless fromVersion?


    #if this message isn't from the logged in user we have problems
    return callback new MessageError(iv, 403) unless user is from


    userExists from, (err, exists) ->
#      return callback new MessageError(iv, 500) if err?
      return callback new MessageError(iv, 404) if not exists
      userExists to, (err, exists) ->
        return callback new MessageError(iv, 500) if err?
        return callback new MessageError(iv, 404) if not exists

        if exists
          #if they're not friends with us or we're not friends with them we have a problem
          isFriend user, to, (err, aFriend) ->
            return callback new MessageError(iv, 500) if err?
            return callback new MessageError(iv, 403) if not aFriend

            cipherdata = message.data
            resendId = message.resendId
            mimeType = message.mimeType
            room = getRoomName(from, to)

            #check for dupes if message has been resent
            checkForDuplicateMessage resendId, user, room, message, (err, found) ->
              return callback new MessageError(iv, 500) if err?
              if found
                logger.debug "found duplicate message, not adding to db"
                sio.sockets.to(to).emit "message", found
                sio.sockets.to(from).emit "message", found
                callback()
              else
                createAndSendMessage from, fromVersion, to, toVersion, iv, cipherdata, mimeType, null, callback


  sio.on "connection", (socket) ->
    user = socket.handshake.session.passport.user

    #join user's room
    logger.debug "user #{user} joining socket.io room"
    socket.join user

    socket.on "message", (data) ->
      handleMessage user, data, (err) ->
        socket.emit "messageError", err if err?


  #delete all messages
  app.delete "/messages/:username", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, (req, res, next) ->

    username = req.user.username
    otherUser = req.params.username
    room = getRoomName username, otherUser

    deleteMyMessages username, otherUser, true, (err) ->
      return next err if err?
      createAndSendMessageControlMessage username, otherUser, room, "deleteAll", room, null, (err) ->
        return next err if err?
        res.send 204


  deleteMyMessages = (username, otherUser, markTheirsDeleted, callback) ->
    room = getRoomName username, otherUser
    getAllMessages room, (err, messages) ->
      return callback err if err?
      ourMessageIds = []
      theirMessageIds = []
      multi = rc.multi()
      async.filter(
        messages
        (item, callback) ->
          oMessage = undefined
          try
            oMessage = JSON.parse(item)
          catch error
            return callback false

          if oMessage.from is username
            ourMessageIds.push oMessage.id
            multi.zrem "messages:#{username}", "messages:#{room}:#{oMessage.id}"

            #delete image from rackspace
            if oMessage.mimeType is 'image/'
              deleteImage oMessage.data

            callback true
          else
            theirMessageIds.push oMessage.id
            callback false
        (results) ->

          if ourMessageIds.length > 0
            #zrem does not handle array as last parameter https://github.com/mranney/node_redis/issues/404
            results.unshift "messages:#{room}"
            #need z remove by score here :( http://redis.io/commands/zrem#comment-845220154
            #remove the messages
            multi.zrem results
            #remove deleted message ids from other user's deleted set as the message is gone now
            multi.srem "deleted:#{otherUser}:#{room}", ourMessageIds
            #remove message pointers


          #todo remove the associated control messages

          if theirMessageIds.length > 0 and markTheirsDeleted
            #add their message id's to our deleted message set
            multi.sadd "deleted:#{username}:#{room}", theirMessageIds


          multi.exec (err, mResults) ->
            return callback err if err?
            callback())


  deleteMessage = (from, to, messageId, notifyMyself, callback) ->
    room = getRoomName to, from
    #get the message we're modifying
    getMessage room, messageId, (err, dMessage) ->
      return callback err if err?
      return callback null, false unless dMessage?

      deleteMessageInternal = (callback) ->
        #if we sent it, delete the data
        if (from is dMessage.from)

          #update message data
          removeMessage dMessage.to, room, messageId, (err, count) ->
            return callback err if err?

            #delete the file if it's a file
            if dMessage.mimeType is "image/"
              deleteImage dMessage.data

            callback()
        else
          #check if user is a user (ie. not deleted) before adding deleted message ids to the set
          rc.sismember "users", from, (err, isUser) ->
            return callback err if err?

            if isUser
              rc.sadd "deleted:#{from}:#{room}", messageId, (err, count) ->
                return callback err if err?
                callback()
            else
                callback()

      deleteMessageInternal (err) ->
        return callback err if err?
        createAndSendMessageControlMessage from, to, room, "delete", room, messageId, (err) ->
          return next err if err?
          if notifyMyself
            createAndSendMessageControlMessage from, from, room, "delete", room, messageId, (err) ->
              return next err if err?
              callback null, true
          else
            callback null, true

  deleteImage = (uri) ->
    splits = uri.split('/')
    path = splits[splits.length - 1]
    logger.debug "removing file from cloud: #{path}"


    retry = 0
    removeFile = (path) ->
      ensureCfClientAuthorized ->
        cfClient.destroyFile rackspaceImageContainer, path, (err) ->
          if err?
            #try to auth once
            if (err.message.indexOf ("Unauthorized") > -1) && (retry is 0)
              retry++
              removeFile path
            else
              logger.error "could not remove file from cloud: #{path}, error: #{err}"
          else
            logger.debug "removed file from cloud: #{path}"

    removeFile path




  #delete single message
  app.delete "/messages/:username/:id", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, (req, res, next) ->

    messageId = req.params.id
    return next new Error 'id required' unless messageId?

    username = req.user.username
    otherUser = req.params.username

    deleteMessage username, otherUser, messageId, false, (err, deleted) ->
      return next err if err?
      res.send (if deleted then 204 else 404)

  app.post "/deletetoken", setNoCache, (req, res, next) ->
    return res.send 400 unless req.body?.username?
    return res.send 400 unless req.body?.authSig?
    return res.send 400 unless req.body?.password?

    username = req.body.username
    password = req.body.password
    authSig = req.body.authSig
    validateUser username, password, authSig, null, (err, status, user) ->
      return next err if err?
      return res.send 403 unless user?

      generateRandomBytes 'base64', (err, token) ->
        return next err if err?
        rc.set "deletetoken:#{username}", token, (err, result) ->
          return next err if err?
          res.send token



  app.post "/passwordtoken", setNoCache, (req, res, next) ->
    return res.send 400 unless req.body?.username?
    return res.send 400 unless req.body?.authSig?
    return res.send 400 unless req.body?.password?

    username = req.body.username
    password = req.body.password
    authSig = req.body.authSig
    validateUser username, password, authSig, null, (err, status, user) ->
      return next err if err?
      return res.send 403 unless user?

      generateRandomBytes 'base64', (err, token) ->
        return next err if err?
        rc.set "passwordtoken:#{username}", token, (err, result) ->
          return next err if err?
          res.send token

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
      removeRoomMessage room, messageId, (err, count) ->
        return next err if err?

        bShareable = shareable is 'true'
        dMessage.shareable = bShareable
        rc.zadd "messages:#{room}", messageId, JSON.stringify(dMessage), (err, addcount) ->
          return next err if err?
          createAndSendMessageControlMessage username, otherUser, room, (if bShareable then "shareable" else "notshareable"), room, messageId, (err) ->
            return next err if err?
            res.send 204

  ensureCfClientAuthorized = (callback) ->
    if not cfClient.authorized
      cfClient.setAuth ->
        callback()
    else
      callback()


  app.post "/images/:username/:version", ensureAuthenticated, validateUsernameExists, validateAreFriends, (req, res, next) ->

    username = req.user.username
    otherUser = req.params.username
    version = req.params.version

    form = new formidable.IncomingForm()
    form.onPart = (part) ->
      return form.handlePart part unless part.filename?
      #  filenames[part.filename] = "uploading"
      iv = part.filename

      outStream = new stream.PassThrough()

      part.on 'data', (buffer) ->
        form.pause()
        #logger.debug 'received part data'
        outStream.write buffer, ->
          form.resume()

      part.on 'end', ->
        form.pause()
        #logger.debug 'received part end'
        outStream.end ->
          form.resume()

      generateRandomBytes 'hex', (err, bytes) ->
        return next err if err?

        path = bytes
        logger.debug "received part: #{part.filename}, uploading to rackspace at: #{path}"

        retry = 0
        postFile = (callback) ->
          ensureCfClientAuthorized ->
            cfClient.addFile rackspaceImageContainer, {remote: path, stream: outStream}, (err, uploaded) ->
              #    rackspace.upload({container: rackspaceImageContainer, remote: path, stream: outStream }, (err) ->
              #todo send messageerror on socket
              if err?
                #try to auth once
                if (err.message.indexOf ("Unauthorized") > -1) && (retry is 0)
                  retry++
                  postFile callback
                else
                  callback err

              else
                callback()



        postFile (err) ->
          return next err if err?

          logger.debug 'uploaded completed'
          url = rackspaceCdnBaseUrl + "/#{path}"

          getFriendImageData username, otherUser, (err, friend) ->
            return next err if err?

            if friend.imageUrl?
              deleteImage friend.imageUrl

            rc.hmset "friendImages:#{username}", "#{otherUser}:imageUrl", url, "#{otherUser}:imageVersion", version, "#{otherUser}:imageIv", iv, (err, status) ->
              return next err if err?
              res.send url

    form.on 'error', (err) ->
      next new Error err

#    form.on 'end', ->
#      logger.debug 'form end'
#      res.send 200

    form.parse req


  app.post "/images/:fromversion/:username/:toversion", ensureAuthenticated, validateUsernameExists, validateAreFriends, (req, res, next) ->
    #upload image to rackspace then create a message with the image url and send it to chat recipients
    #uris = []

#    filenames = {}
 #   complete = false
  #  formEnded = false
   # resSent = false
    username = req.user.username

    form = new formidable.IncomingForm()
    form.onPart = (part) ->
      return form.handlePart part unless part.filename?
    #  filenames[part.filename] = "uploading"
      iv = part.filename

      outStream = new stream.PassThrough()

      part.on 'data', (buffer) ->
        form.pause()
        #logger.debug 'received part data'
        outStream.write buffer, ->
          form.resume()


      part.on 'end', ->
        form.pause()
        #logger.debug 'received part end'
        outStream.end ->
          form.resume()

      room = getRoomName username, req.params.username
      getNextMessageId room, null, (id) ->
        #todo send message error on socket
        if not id?
          logger.error new Error 'could not generate messageId'
          sio.sockets.to(username).emit "messageError", new MessageError(iv, 'could not generate message id')
          return# delete filenames[part.filename]


        generateRandomBytes 'hex', (err, bytes) ->
          if err?
            logger.error err
            sio.sockets.to(username).emit "messageError", new MessageError(iv, 'could not generate unique filename')
            return #delete filenames[part.filename]

          path = bytes
          logger.debug "received part: #{part.filename}, uploading to rackspace at: #{path}"

          retry = 0
          postFile = (callback) ->
            ensureCfClientAuthorized ->
              cfClient.addFile rackspaceImageContainer, {remote: path, stream: outStream}, (err, uploaded) ->
                #    rackspace.upload({container: rackspaceImageContainer, remote: path, stream: outStream }, (err) ->
                #todo send messageerror on socket
                if err?
                  #try to auth once
                  if (err.message.indexOf ("Unauthorized") > -1) && (retry is 0)
                    retry++
                    postFile callback
                  else
                    callback err

                else
                  callback()



          postFile (err) ->
            if err?
              logger.error err
              sio.sockets.to(username).emit "messageError", new MessageError(iv, 'error uploading file')
              return #delete filenames[part.filename]

            logger.debug 'uploaded completed'
            uri = rackspaceCdnBaseUrl + "/#{path}"
            #uris.push uri
            createAndSendMessage(req.user.username, req.params.fromversion, req.params.username, req.params.toversion, part.filename, uri, "image/", id, (err) ->
              logger.error "error sending message on socket: #{err}" if err?
              #return delete filenames[part.filename]

              #filenames[part.filename] = uri

#              allCompleted = true
#              for filename in filenames
#                if filenames[filename] is 'uploading'
#                  allCompleted = false
#                  break
#
#              complete = allCompleted
#              if complete and formEnded and not resSent
#                logger.debug 'uploads complete'
#                res.send filenames
#                resSent = true
            )

        #logger.debug 'stream piped'
        #paused.resume()


    form.on 'error', (err) ->
      next new Error err

    form.on 'end', ->
      logger.debug 'form end'
      #formEnded = true

#      allCompleted = true
#      for filename in filenames
#        if filenames[filename] is 'uploading'
#          allCompleted = false
#          break
#
#      complete = allCompleted
#      if complete and not resSent
#
#        logger.debug 'uploads complete'
      res.send 200
        #resSent = true



    form.parse req




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
#  app.get "/messages/:username", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, setNoCache, (req, res, next) ->
#    #return last x messages
#    getMessages req.user.username, getRoomName(req.user.username, req.params.username), 30, (err, data) ->
#      #    rc.zrange "messages:" + getRoomName(req.user.username, req.params.remoteuser), -50, -1, (err, data) ->
#      return next err if err?
#      res.send data

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

  #todo figure out caching
  app.get "/publickeys/:username", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, setNoCache, getPublicKeys
  app.get "/publickeys/:username/:version", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted, setCache(oneYear), getPublicKeys
  app.get "/keyversion/:username", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeleted,(req, res, next) ->
    rc.get "keyversion:#{req.params.username}", (err, version) ->
      return callback err if err?
      res.send version

  app.get "/users/:username/exists", setNoCache, (req, res, next) ->
    userExistsOrDeleted req.params.username, (err, exists) ->
      return next err if err?
      res.send exists

  handleReferrers = (username, referrers, callback) ->
    return callback() if referrers.length is 0
    usersToInvite = []
    multi = rc.multi()
    async.each(
      referrers,
      (referrer, callback) ->
        referralUserName = referrer.utm_content
        usersToInvite.push referralUserName
        multi.sismember "users", referralUserName
        callback()
      (err) ->
        return callback err if err?

        multi.exec (err, results) ->
          return callback err if err?
          _.each(
            results,
            (exists, index, list) ->
              if exists
                #send invite
                inviteUser username, usersToInvite[index], (err, inviteSent) ->
                  logger.error err if err?
          )
          callback())


  createNewUser = (req, res, next) ->
    username = req.body.username
    password = req.body.password
    logger.debug "/users, username: #{username}, password: #{password}"

    #return next new Error('username required') unless username?
    #return next new Error('password required') unless password?

    userExistsOrDeleted username, (err, exists) ->
      return next err if err?
      if exists
        logger.debug "user already exists"
        return res.send 409
      else


        user = {}
        user.username = username

        keys = {}
        if req.body?.dhPub?
          keys.dhPub = req.body.dhPub
        else
          return next new Error('dh public key required')

        if req.body?.dsaPub?
          keys.dsaPub = req.body.dsaPub
        else
          return next new Error('dsa public key required')

        return next new Error('auth signature required') unless req.body?.authSig?

        if req.body?.gcmId?
          user.gcmId = req.body.gcmId


        referrers = undefined

        if req.body?.referrers?
          try
            referrers = JSON.parse(req.body.referrers)
          catch error
            logger.error error
            return next error


        logger.debug "gcmID: #{user.gcmId}"
        logger.debug "referrers: #{referrers}"

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
              keysKey = "keys:#{username}"
              keys.version = kv + ""
              multi.hmset userKey, user
              multi.hset keysKey, kv, JSON.stringify(keys)
              multi.sadd "users", username
              multi.exec (err,replies) ->
                return next err if err?
                logger.debug "created user: #{username}"
                req.login user, ->
                  req.user = user
                  if referrers
                    handleReferrers username, referrers, next
                  else
                    next()



  app.post "/users", validateUsernamePassword, createNewUser, passport.authenticate("local"), (req, res, next) ->
    res.send 201

  app.post "/login", passport.authenticate("local"), (req, res, next) ->
    username = req.user.username
    logger.debug "/login post, user #{username}, referrers: #{req.body.referrers}"
    if req.body?.referrers?
      try
        referrers = JSON.parse(req.body.referrers)
        handleReferrers username, referrers, (err) ->
          return next err if err?
          res.send 204

      catch error
        return next error
    else
      res.send 204

  app.post "/keytoken", setNoCache, (req, res, next) ->
    return res.send 400 unless req.body?.username?
    return res.send 400 unless req.body?.authSig?
    return res.send 400 unless req.body?.password?

    username = req.body.username
    password = req.body.password
    authSig = req.body.authSig
    validateUser username, password, authSig, null, (err, status, user) ->
      return next err if err?
      return res.send 403 unless user?

      #the user wants to update their key so we will generate a token that the user signs to make sure they're not using a replay attack of some kind
      #get the current version
      rc.get "keyversion:#{username}", (err, currkv) ->
        return next err if err?

        #inc key version
        kv = parseInt(currkv) + 1
        generateRandomBytes 'base64',(err, token) ->
          return next err if err?
          rc.set "keytoken:#{username}", token, (err, result) ->
            return next err if err?
            res.send {keyversion: kv, token: token}

  app.post "/keys", (req, res, next) ->
    logger.debug "/keys"
    return res.send 400 unless req.body?.username?
    return res.send 400 unless req.body?.authSig?
    return res.send 400 unless req.body?.password?
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
        return next new Error 'no keytoken exists' unless rtoken?
        newKeys = {}
        newKeys.dhPub = req.body.dhPub
        newKeys.dsaPub = req.body.dsaPub
        logger.debug "received token signature: " + req.body.tokenSig
        logger.debug "received auth signature: " + req.body.authSig
        logger.debug "token: " + rtoken

        password = req.body.password

        #validate the signature against the token

        getLatestKeys username, (err, keys) ->
          return next err if err?
          return next new Error "no keys exist for user #{username}" unless keys?

          verified = verifySignature new Buffer(rtoken, 'base64'), new Buffer(password), req.body.tokenSig, keys.dsaPub
          return res.send 403 unless verified

          authSig = req.body.authSig
          validateUser username, password, authSig, null, (err, status, user) ->
            return next err if err?
            return res.send 403 unless user?

            #delete the token of which there should only be one
            rc.del "keytoken:#{username}", (err, rdel) ->
              return next err if err?
              return res.send 404 unless rdel is 1

              #sign the keys
              newKeys.dhPubSig = crypto.createSign('sha256').update(new Buffer(newKeys.dhPub)).sign(serverPrivateKey, 'base64')
              newKeys.dsaPubSig = crypto.createSign('sha256').update(new Buffer(newKeys.dsaPub)).sign(serverPrivateKey, 'base64')
              logger.debug "saving keys #{username}, dhPubSig: #{newKeys.dhPubSig}, dsaPubSig: #{newKeys.dsaPubSig}"

              keysKey = "keys:#{username}"
              newKeys.version = storedkv + ""
              #add the keys to the key set and add revoke message in transaction
              multi = rc.multi()
              multi.hset keysKey, kv, JSON.stringify(newKeys)
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

                  createAndSendUserControlMessage username, "added", friendname, null, (err) ->
                    return next err if err?
                    sendInviteResponseGcm username, friendname, 'accept', (result) ->
                      createAndSendUserControlMessage friendname, "added", username, null, (err) ->
                        return next err if err?
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
              createAndSendUserControlMessage username, 'ignore', username, null, (err) ->
                return next err if err?
                res.send 204

          when 'block'
            rc.sadd "blocked:#{username}", friendname, (err, data) ->
              return next err if err?
              createAndSendUserControlMessage friendname, 'ignore', username, null, (err) ->
                return next err if err?
                createAndSendUserControlMessage username, 'ignore', username, null, (err) ->
                  return next err if err?
                  res.send 204

          else return next new Error 'invalid action'


  getFriendImageData = (username, friendname, callback) ->
    rc.hmget "friendImages:#{username}", "#{friendname}:imageUrl", "#{friendname}:imageVersion", "#{friendname}:imageIv", (err, friendImageData) ->
      return callback err if err?
      callback null, new Friend friendname, 0, friendImageData[0], friendImageData[1], friendImageData[2]


  getFriends = (req, res, next) ->
    username = req.user.username
    #get users we're friends with
    rc.smembers "friends:#{username}", (err, rfriends) ->
      return next err if err?
      friends = []
      return res.send {} unless rfriends?

      _.each rfriends, (name) ->
        #todo use bulk operation
        getFriendImageData username, name, (err, friend) ->
          return next err if err?
          friends.push friend

      #get users that invited us
      rc.smembers "invites:#{username}", (err, invites) ->
        return next err if err?
        _.each invites, (name) -> friends.push new Friend name, 32

        #get users that we invited
        rc.smembers "invited:#{username}", (err, invited) ->
          return next err if err?
          _.each invited, (name) -> friends.push new Friend name, 2

          #get users that deleted us that we haven't deleted
          rc.smembers "users:deleted:#{username}", (err, deleted) ->
            return next err if err?
            _.each deleted, (name) ->

              friend = friends.filter (friend) -> friend.name is name

              if not friend?
                friends.push new Friend name, 1
              else
                friend.name += 1


            rc.get "control:user:#{username}:id", (err, id) ->
              friendstate = {}
              friendstate.userControlId = id ? 0
              friendstate.friends = friends

              sFriendState = JSON.stringify friendstate
              logger.debug ("friendstate: " + sFriendState)
              res.send sFriendState

  app.get "/friends", ensureAuthenticated, setNoCache, getFriends

  app.post "/users/delete", (req, res, next) ->
    logger.debug "/users/delete"
    return res.send 400 unless req.body?.username?
    return res.send 400 unless req.body?.authSig?
    return res.send 400 unless req.body?.password?
    return next new Error 'key version required' unless req.body?.keyVersion?
    return next new Error 'token signature required' unless req.body?.tokenSig?


    #make sure the key versions match
    username = req.body.username

    kv = req.body.keyVersion
    logger.debug "signed with keyversion: " + kv
    #todo transaction
    #make sure the tokens match
    rc.get "deletetoken:#{username}", (err, rtoken) ->
      return next new Error 'no delete token' unless rtoken?
      logger.debug "token: " + rtoken

      password = req.body.password

      #validate the signature against the token

      getKeys username, kv, (err, keys) ->
        return next err if err?
        return next new Error "no keys exist for user #{username}" unless keys?

        #verified = crypto.createVerify('sha256').update(token).update(new Buffer(password)).verify(keys.dsaPub, new Buffer(req.body.tokenSig, 'base64'))

        verified = verifySignature new Buffer(rtoken, 'base64'), new Buffer(password), req.body.tokenSig, keys.dsaPub
        return res.send 403 unless verified

        authSig = req.body.authSig
        validateUser username, password, authSig, null, (err, status, user) ->
          return next(err) if err?
          return res.send 403 unless user?

          #delete the token of which there should only be one
          rc.del "deletetoken:#{username}", (err, rdel) ->
            return next err if err?
            return res.send 404 unless rdel is 1

            #copy data from user's list of friends to list of deleted users friends
            rc.smembers "friends:#{username}", (err, friends) ->
              return next err if err?


              addDeletedFriend = (friends, callback) ->
                if friends.length > 0
                  rc.sadd "deleted:#{username}", friends, (err, nadded) ->
                    return next err if err?
                    callback()
                else
                  callback()

              addDeletedFriend friends, (err) ->
                return next err if err?
                multi = rc.multi()
                #remove them from the global set of users
                multi.srem "users", username

                #add them to the global set of deleted users
                multi.sadd "deleted", username

                multi.del "users:#{username}"

                #add user to each friend's set of deleted users
                async.each(
                  friends,
                  (friend, callback) ->
                    deleteUser username, friend, multi, (err) ->
                      return callback err if err?

                      #tell them we've been deleted
                      createAndSendUserControlMessage friend, "delete", username, username, (err) ->
                        return callback err if err?
                        callback()
                  (err) ->
                    return next err if err?

                    #if we don't have any friends aww, just blow everything away
                    if friends.length is 0
                      deleteRemainingIdentityData multi, username

                    multi.exec (err, replies) ->
                      return next err if err?
                      createAndSendUserControlMessage username, "revoke", username, parseInt(kv) + 1, (err) ->
                        return next err if err?
                        res.send 204)


  app.put "/users/password", (req, res, next) ->
    logger.debug "/users/password"
    return res.send 400 unless req.body?.username?
    return res.send 400 unless req.body?.authSig?
    return res.send 400 unless req.body?.password?
    return next new Error 'newPassword required' unless req.body?.newPassword?
    return next new Error 'keyVersion required' unless req.body?.keyVersion?
    return next new Error 'tokenSig required' unless req.body?.tokenSig?


    #make sure the key versions match
    username = req.body.username

    kv = req.body.keyVersion
    logger.debug "signed with keyversion: " + kv
    #todo transaction
    #make sure the tokens match
    rc.get "passwordtoken:#{username}", (err, rtoken) ->
      return next new Error 'no password token' unless rtoken?
      logger.debug "token: " + rtoken

      password = req.body.password
      newPassword = req.body.newPassword
      #validate the signature against the token

      getKeys username, kv, (err, keys) ->
        return next err if err?
        return next new Error "no keys exist for user #{username}" unless keys?

        verified = verifySignature new Buffer(rtoken, 'base64'), new Buffer(newPassword), req.body.tokenSig, keys.dsaPub
        return res.send 403 unless verified

        authSig = req.body.authSig
        validateUser username, password, authSig, null, (err, status, user) ->
          return next(err) if err?
          return res.send 403 unless user?

          #delete the token of which there should only be one
          rc.del "passwordtoken:#{username}", (err, rdel) ->
            return next err if err?
            return res.send 404 unless rdel is 1

            bcrypt.genSalt 10, 32, (err, salt) ->
              return next err if err?

              bcrypt.hash newPassword, salt, (err, hashedPassword) ->
                return next err if err?
                rc.hset "users:#{username}", "password", hashedPassword, (err, set) ->
                  return next err if err?
                  res.send 204


  app.delete "/friends/:username", ensureAuthenticated, validateUsernameExists, validateAreFriendsOrDeletedOrInvited, (req, res, next) ->
    username = req.user.username
    theirUsername = req.params.username

    multi = rc.multi()
    deleteUser username, theirUsername, multi, (err) ->
      return next err if err?

      #tell (todo) other connections logged in as us that we deleted someone
      createAndSendUserControlMessage username, "delete", theirUsername, username, (err) ->
        return next err if err?
        #tell them they've been deleted
        createAndSendUserControlMessage theirUsername, "delete", username, username, (err) ->
          return next err if err?
          multi.exec (err, results) ->
            return next err if err?
            res.send 204

  deleteRemainingIdentityData = (multi, username) ->
    #cleanup stuff
    multi.srem "deleted", username
    multi.del "keys:#{username}"
    multi.del "keyversion:#{username}"
    multi.del "control:user:#{username}"
    multi.del "control:user:#{username}:id"


  deleteUser = (username, theirUsername, multi, next) ->
    #check if they've only been invited
    rc.sismember "invited:#{username}", theirUsername, (err, isInvited) ->
      return next err if err?
      if isInvited
        deleteInvites theirUsername, username, (err) ->
          return next err if err?
          next()
      else
        room = getRoomName username, theirUsername
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
            #get the latest id
            rc.get "#{room}:id", (err, id) ->

              #handle no id
              deleteMessages = (messageId, callback) ->
                if messageId?
                  deleteMyMessages username, theirUsername, false, (err) ->
                    callback err if err?
                    callback()
                else
                  callback()

              deleteMessages id, (err) ->
                return next err if err?
                #delete friend association
                multi.srem "friends:#{username}", theirUsername
                multi.srem "friends:#{theirUsername}", username

                #add me to their set of deleted users if they're not deleted
                rc.sismember "deleted", theirUsername, (err, isDeleted) ->
                  callback err if err?
                  if not isDeleted
                    multi.sadd "users:deleted:#{theirUsername}", username
                  next()

          #they've already deleted me
          else
            #remove them from their deleted set (if they deleted their identity)
            rc.srem "deleted:#{theirUsername}", username, (err, rCount) ->
              return next err if err?
              #if they have been deleted and we are the last person to delete them
              #remove the final pieces of data
              rc.sismember "deleted", theirUsername, (err, isDeleted) ->
                return next err if err?

                deleteLastUserScraps = (callback) ->

                  if isDeleted
                    rc.scard "deleted:#{theirUsername}", (err, card) ->
                      callback err if err?
                      if card is 0


                        deleteRemainingIdentityData multi, theirUsername
                        callback()
                      else
                        callback()
                  else
                    callback()

                deleteLastUserScraps (err) ->
                  return next err if err?


                  #delete control message data
                  multi.del "control:message:#{room}"
                  multi.del "control:message:#{room}:id"

                  #remove them from my deleted set
                  multi.srem "users:deleted:#{username}", theirUsername


                  #delete message data
                  multi.del "#{room}:id"
                  multi.del "messages:#{room}"
                  next()


  app.post "/logout", ensureAuthenticated, (req, res) ->
    req.logout()
    res.send 204

  generateRandomBytes = (encoding, callback) ->
    rc.incr "uniqueKeySeed", (err, seed) ->
      hash = crypto.createHash("sha1").update('' + seed).digest(encoding)
      callback null, hash

  comparePassword = (password, dbpassword, callback) ->
    bcrypt.compare password, dbpassword, callback

  getLatestKeys = (username, callback) ->
    rc.get "keyversion:#{username}", (err, version) ->
      return callback err if err?
      return callback new Error 'no keys exist for user: #{username}' unless version?
      getKeys username, version, callback

  getKeys = (username, version, callback) ->
    rc.hget "keys:#{username}", version, (err, keys) ->
      return callback err if err?

      jkeys = undefined
      try
        jkeys = JSON.parse(keys)
      catch error
        return callback error

      callback null, jkeys


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

