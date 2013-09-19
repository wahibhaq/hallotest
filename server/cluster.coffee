###

  surespot node.js server
  copyright 2fours LLC
  written by Adam Patacchiola adam@2fours.com

###
env = process.env.SURESPOT_ENV ? 'Local' # one of "Local","Stage", "Prod"
if env is 'Prod'
  NODETIME_API_KEY=process.env.SURESPOT_NODETIME_API_KEY
  require('nodetime').profile({
    accountKey: NODETIME_API_KEY,
    appName: 'surespot'
  })

cluster = require('cluster')
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
pkgcloud = require 'pkgcloud'
utils = require('connect/lib/utils')
pause = require 'pause'
rstream = require 'readable-stream'
redbacklib = require 'redback'
googleapis = require 'googleapis'



#constants
USERNAME_LENGTH = 20
CONTROL_MESSAGE_HISTORY = 100
MAX_MESSAGE_LENGTH = 500000
MAX_HTTP_REQUEST_LENGTH = 500000
NUM_CORES =  parseInt(process.env.SURESPOT_CORES) ? 4
GCM_TTL = 604800

oneYear = 31536000000
oneDay = 86400

#config

#rate limit to MESSAGE_RATE_LIMIT_RATE / MESSAGE_RATE_LIMIT_SECS (seconds) (allows us to get request specific on top of iptables)
RATE_LIMITING_MESSAGE=process.env.SURESPOT_RATE_LIMITING_MESSAGE is "true"
RATE_LIMITING_PING=process.env.SURESPOT_RATE_LIMITING_PING is "true"
RATE_LIMITING_EXISTS=process.env.SURESPOT_RATE_LIMITING_EXISTS is "true"
RATE_LIMITING_CREATE_USER=process.env.SURESPOT_RATE_LIMITING_CREATE_USER is "true"

RATE_LIMIT_BUCKET_MESSAGE = process.env.SURESPOT_RATE_LIMIT_BUCKET_MESSAGE ? 5
RATE_LIMIT_SECS_MESSAGE = process.env.SURESPOT_RATE_LIMIT_SECS_MESSAGE ? 10
RATE_LIMIT_RATE_MESSAGE = process.env.SURESPOT_RATE_LIMIT_RATE_MESSAGE ? 100

RATE_LIMIT_BUCKET_PING = process.env.SURESPOT_RATE_LIMIT_BUCKET_PING ? 60
RATE_LIMIT_SECS_PING = process.env.SURESPOT_RATE_LIMIT_SECS_PING ? 10
RATE_LIMIT_RATE_PING = process.env.SURESPOT_RATE_LIMIT_RATE_PING ? 100

RATE_LIMIT_BUCKET_EXISTS = process.env.SURESPOT_RATE_LIMIT_BUCKET_EXISTS ? 20
RATE_LIMIT_SECS_EXISTS = process.env.SURESPOT_RATE_LIMIT_SECS_EXISTS ? 10
RATE_LIMIT_RATE_EXISTS = process.env.SURESPOT_RATE_LIMIT_RATE_EXISTS ? 100

RATE_LIMIT_BUCKET_CREATE_USER = process.env.SURESPOT_RATE_LIMIT_BUCKET_CREATE_USER ? 600
RATE_LIMIT_SECS_CREATE_USER = process.env.SURESPOT_RATE_LIMIT_SECS_CREATE_USER ? 86400
RATE_LIMIT_RATE_CREATE_USER = process.env.SURESPOT_RATE_LIMIT_RATE_CREATE_USER ? 1000

MESSAGES_PER_USER = process.env.SURESPOT_MESSAGES_PER_USER ? 20
debugLevel = process.env.SURESPOT_DEBUG_LEVEL ? 'debug'
database = process.env.SURESPOT_DB ? 0
socketPort = process.env.SURESPOT_SOCKET ? 443
googleApiKey = process.env.SURESPOT_GOOGLE_API_KEY
googleClientId = process.env.SURESPOT_GOOGLE_CLIENT_ID
googleClientSecret = process.env.SURESPOT_GOOGLE_CLIENT_SECRET
googleRedirectUrl = process.env.SURESPOT_GOOGLE_REDIRECT_URL
rackspaceApiKey = process.env.SURESPOT_RACKSPACE_API_KEY
rackspaceCdnBaseUrl = process.env.SURESPOT_RACKSPACE_CDN_URL
rackspaceImageContainer = process.env.SURESPOT_RACKSPACE_IMAGE_CONTAINER
rackspaceUsername = process.env.SURESPOT_RACKSPACE_USERNAME
sessionSecret = process.env.SURESPOT_SESSION_SECRET
logConsole = process.env.SURESPOT_LOG_CONSOLE is "true"
redisPort = process.env.REDIS_PORT
redisSentinelPort = parseInt(process.env.SURESPOT_REDIS_SENTINEL_PORT) ? 6379
redisSentinelHostname = process.env.SURESPOT_REDIS_SENTINEL_HOSTNAME ? "127.0.0.1"
redisPassword = process.env.SURESPOT_REDIS_PASSWORD ? null
useRedisSentinel = process.env.SURESPOT_USE_REDIS_SENTINEL is "true"
bindAddress = process.env.SURESPOT_BIND_ADDRESS ? "0.0.0.0"
dontUseSSL = process.env.SURESPOT_DONT_USE_SSL is "true"
useSSL = not dontUseSSL


http = if useSSL then require 'https' else require 'http'


logger.remove logger.transports.Console
#logger.setLevels logger.config.syslog.levels
logger.exitOnError = true
logger.emitErrs = false

transports = []
transports.push new (logger.transports.File)({ dirname: 'logs', filename: 'server.log', maxsize: 5000000, maxFiles: 20, json: false, level: debugLevel, handleExceptions: true })
#always use file transport
logger.add transports[0], null, true


numCPUs = require('os').cpus().length

if NUM_CORES > numCPUs then NUM_CORES = numCPUs

if env is 'Local' or logConsole
  transports.push new (logger.transports.Console)({colorize: true, timestamp: true, level: debugLevel, handleExceptions: true })
  logger.add transports[1], null, true


logger.debug "__dirname: #{__dirname}"


if (cluster.isMaster and NUM_CORES > 1)
  # Fork workers.
  for i in [0..NUM_CORES-1]
    cluster.fork();

  cluster.on 'online', (worker, code, signal) ->
    logger.debug 'worker ' + worker.process.pid + ' online'

  cluster.on 'exit', (worker, code, signal) ->
    logger.debug "worker #{worker.process.pid} died, forking another"
    cluster.fork()

  logger.info "env: #{env}"
  logger.info "database: #{database}"
  logger.info "socket: #{socketPort}"
  logger.info "address: #{bindAddress}"
  logger.info "ssl: #{useSSL}"
  logger.info "rate limiting messages: #{RATE_LIMITING_MESSAGE}, int: #{RATE_LIMIT_BUCKET_MESSAGE}, secs: #{RATE_LIMIT_SECS_MESSAGE}, rate: #{RATE_LIMIT_RATE_MESSAGE}"
  logger.info "rate limiting ping: #{RATE_LIMITING_PING}, int: #{RATE_LIMIT_BUCKET_PING}, secs: #{RATE_LIMIT_SECS_PING}, rate: #{RATE_LIMIT_RATE_PING}"
  logger.info "rate limiting exists: #{RATE_LIMITING_EXISTS}, int: #{RATE_LIMIT_BUCKET_EXISTS}, secs: #{RATE_LIMIT_SECS_EXISTS}, rate: #{RATE_LIMIT_RATE_EXISTS}"
  logger.info "rate limiting create users: #{RATE_LIMITING_CREATE_USER}, int: #{RATE_LIMIT_BUCKET_CREATE_USER}, secs: #{RATE_LIMIT_SECS_CREATE_USER}, rate: #{RATE_LIMIT_RATE_CREATE_USER}"
  logger.info "messages per user: #{MESSAGES_PER_USER}"
  logger.info "debug level: #{debugLevel}"
  logger.info "google api key: #{googleApiKey}"
  logger.info "rackspace api key: #{rackspaceApiKey}"
  logger.info "rackspace cdn url: #{rackspaceCdnBaseUrl}"
  logger.info "rackspace image container: #{rackspaceImageContainer}"
  logger.info "rackspace username: #{rackspaceUsername}"
  logger.info "session secret: #{sessionSecret}"
  logger.info "cores: #{NUM_CORES}"
  logger.info "console logging: #{logConsole}"
  logger.info "nodetime api key: #{NODETIME_API_KEY}"
  logger.info "use redis sentinel: #{useRedisSentinel}"
  logger.info "redis sentinel hostname: #{redisSentinelHostname}"
  logger.info "redis sentinel port: #{redisSentinelPort}"
  logger.info "redis password: #{redisPassword}"

else

  if NUM_CORES is 1
    logger.info "env: #{env}"
    logger.info "database: #{database}"
    logger.info "socket: #{socketPort}"
    logger.info "address: #{bindAddress}"
    logger.info "ssl: #{useSSL}"
    logger.info "rate limiting messages: #{RATE_LIMITING_MESSAGE}, secs: #{RATE_LIMIT_SECS_MESSAGE}, rate: #{RATE_LIMIT_RATE_MESSAGE}"
    logger.info "rate limiting ping: #{RATE_LIMITING_PING}, secs: #{RATE_LIMIT_SECS_PING}, rate: #{RATE_LIMIT_SECS_MESSAGE}"
    logger.info "rate limiting exists: #{RATE_LIMITING_EXISTS}, secs: #{RATE_LIMIT_SECS_EXISTS}, rate: #{RATE_LIMIT_RATE_EXISTS}"
    logger.info "rate limiting create users: #{RATE_LIMITING_CREATE_USER}, secs: #{RATE_LIMIT_SECS_CREATE_USER}, rate: #{RATE_LIMIT_RATE_CREATE_USER}"
    logger.info "messages per user: #{MESSAGES_PER_USER}"
    logger.info "debug level: #{debugLevel}"
    logger.info "google api key: #{googleApiKey}"
    logger.info "rackspace api key: #{rackspaceApiKey}"
    logger.info "rackspace cdn url: #{rackspaceCdnBaseUrl}"
    logger.info "rackspace image container: #{rackspaceImageContainer}"
    logger.info "rackspace username: #{rackspaceUsername}"
    logger.info "session secret: #{sessionSecret}"
    logger.info "cores: #{NUM_CORES}"
    logger.info "console logging: #{logConsole}"
    logger.info "nodetime api key: #{NODETIME_API_KEY}"
    logger.info "redis sentinel hostname: #{redisSentinelHostname}"
    logger.info "redis sentinel port: #{redisSentinelPort}"
    logger.info "redis password: #{redisPassword}"
    logger.info "use redis sentinel: #{useRedisSentinel}"


  sio = undefined
  sessionStore = undefined
  rc = undefined
  rcs = undefined
  pub = undefined
  sub = undefined
  redback = undefined
  client = undefined
  client2 = undefined
  app = undefined
  ssloptions = undefined
  oauth2Client = undefined

  rackspace = pkgcloud.storage.createClient {provider: 'rackspace', username: rackspaceUsername, apiKey: rackspaceApiKey}



  redis = undefined
  if useRedisSentinel
    redis = require 'redis-sentinel-client'
  else
    #use forked redis
    redis = require 'redis'

  createRedisClient = (database, port, host, password) ->
    if port? and host?
      tempclient = null
      if useRedisSentinel
        sentinel = redis.createClient(port,host)
        tempclient = sentinel.getMaster()

        sentinel.on 'error', (err) -> logger.error err
        tempclient.on 'error', (err) -> logger.error err
      else
        tempclient = redis.createClient(port,host)

      if password?
        tempclient.auth password
      #if database?
       # tempclient.select database
        #return tempclient

      else
        return tempclient
    else
      logger.debug "creating local redis client"
      tempclient = null

      if useRedisSentinel
        sentinel = redis.createClient(26379, "127.0.0.1")
        tempclient = sentinel.getMaster()

        sentinel.on 'error', (err) -> logger.error err
        tempclient.on 'error', (err) -> logger.error err
      else
        tempclient = redis.createClient()

      if database?
        tempclient.select database
        return tempclient
      else
        return tempclient
  #ec
  serverPrivateKey = undefined
  serverPrivateKey = fs.readFileSync("ec#{env}/priv.pem")

  #ssl
  if useSSL
    ssloptions = {
    key: fs.readFileSync("ssl#{env}/surespot.key"),
    cert: fs.readFileSync("ssl#{env}/surespot.crt")
    }

    peerCertPath = "ssl#{env}/PositiveSSLCA2.crt"
    if fs.existsSync(peerCertPath)
      ssloptions["ca"] = fs.readFileSync(peerCertPath)

  # create EC keys like so
  # priv key
  # openssl ecparam -name secp521r1 -outform PEM -out priv.pem -genkey
  # pub key
  # openssl ec -inform PEM  -outform PEM -in priv.pem -out pub.pem -pubout
  #
  # verify signature like so
  # openssl dgst -sha256 -verify key -signature sig.bin data

  rc = createRedisClient database, redisSentinelPort, redisSentinelHostname, redisPassword
  rcs = createRedisClient database, redisSentinelPort, redisSentinelHostname, redisPassword
  pub = createRedisClient database, redisSentinelPort, redisSentinelHostname, redisPassword
  sub = createRedisClient database, redisSentinelPort, redisSentinelHostname, redisPassword
  client = createRedisClient database, redisSentinelPort, redisSentinelHostname, redisPassword
  client2 = createRedisClient database, redisSentinelPort, redisSentinelHostname, redisPassword

  redback = redbacklib.use rc
  ratelimiterexists = redback.createRateLimit('rle', { bucket_interval: RATE_LIMIT_BUCKET_EXISTS } )
  ratelimiterping = redback.createRateLimit('rlp', { bucket_interval: RATE_LIMIT_BUCKET_PING })
  ratelimitercreateuser = redback.createRateLimit('rlu', { bucket_interval: RATE_LIMIT_BUCKET_CREATE_USER })
  ratelimitermessages = redback.createRateLimit('rlm', { bucket_interval: RATE_LIMIT_BUCKET_MESSAGE })


  app = express()
  app.configure ->
    sessionStore = new RedisStore({
      client: client
    })

    app.use express.limit(MAX_HTTP_REQUEST_LENGTH)
    app.use express.compress()
    app.use express.cookieParser()
    app.use express.json()
    app.use express.urlencoded()

    app.use express.session(
      secret: sessionSecret
      store: sessionStore
      cookie: { maxAge: (oneDay*3000) }
      proxy: true
    )
    app.use passport.initialize()
    app.use passport.session({pauseStream: true})
    app.use expressWinston.logger({
    transports: transports
    level: debugLevel
    })
    app.use app.router
    app.use expressWinston.errorLogger({
    transports: transports
    level: "warn"
    })

    app.use (err, req, res, next) ->
      res.send err.status or 500






  http.globalAgent.maxSockets = Infinity

  server = if useSSL then http.createServer ssloptions, app else http.createServer app
  server.listen socketPort, bindAddress
  sio = require("socket.io").listen server


  #winston up some socket.io
  sio.set "logger", {debug: logger.debug, info: logger.info, warn: logger.warn, error: logger.error }


  sioRedisStore = require("socket.io/lib/stores/redis")
  sio.set "store", new sioRedisStore(
    #use forked redis
    redis: require 'redis-sentinel-client/node_modules/redis'
    redisPub: pub
    redisSub: sub
    redisClient: client2
  )

  sio.set 'transports', ['websocket']
  sio.set 'destroy buffer size', MAX_MESSAGE_LENGTH
  sio.set 'browser client', false


  sio.set "authorization", (req, accept) ->
    logger.debug 'socket.io auth'
    if req.headers.cookie
      parsedCookie = cookie.parse(req.headers.cookie)
      connectSid = parsedCookie["connect.sid"]
      return accept 'no cookie', false unless connectSid?

      req.sessionID = utils.parseSignedCookie(connectSid, sessionSecret)
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

  typeIsArray = Array.isArray || ( value ) -> return {}.toString.call( value ) is '[object Array]'

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
    rc.sismember "u", username, (err, isMember) ->
      return fn err if err?
      return fn null, if isMember then true else false


  userExistsOrDeleted = (username, checkReserved, fn) ->
    rc.sismember "u", username, (err, isMember) ->
      return fn err if err?
      return fn null, true if isMember
      rc.sismember "d", username, (err, isMember) ->
        return fn err if err?
        return fn null, true if isMember
        return fn null, false if not checkReserved
        rc.sismember "r", username, (err, isMember) ->
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
    userExists req.params.username, (err, exists) ->
      if err?
        paused.resume()
        return next err


      if not exists
        paused.resume()
        return res.send 404


      next()
      paused.resume()

  validateUsernameExistsOrDeleted = (req, res, next) ->
    #pause and resume events - https://github.com/felixge/node-formidable/issues/213
    paused = pause req
    userExistsOrDeleted req.params.username, false, (err, exists) ->
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
        rc.sismember "ud:#{username}", friendname, (err, isDeleted) ->
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
        rc.sismember "ud:#{username}", friendname, (err, isDeleted) ->
          return next err if err?
          if isDeleted
            next()
          else
            #we invited someone
            rc.sismember "is:#{username}", friendname, (err, isInvited) ->
              return next err if err?
              if isInvited
                next()
              else
                res.send 403


  #is friendname a friend of username
  isFriend = (username, friendname, callback) ->
    rc.sismember "f:#{username}", friendname, callback

  hasConversation = (username, room, callback) ->
    rc.sismember "c:#{username}", room, callback

  inviteExists = (username, friendname, callback) ->
    rc.sismember "is:#{username}", friendname, (err, result) =>
      return callback err if err?
      return callback null, false if not result
      rc.sismember "ir:#{friendname}", username, callback

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
    rc.zrangebyscore "m:" + room, id, id, (err, data) ->
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


  #oauth crap
  #code = "4/wes40DoudPlswVgl8EV4ihpGcuef.sq7QN70kr3QYmmS0T3UFEsMgH4BtggI"
  getAccessToken = (oauth2client, callback) ->
    code = "4/U9d1h9YdNRCkysQtUjXBfR7udSCy.4nL-EjcxeRYTmmS0T3UFEsOeSrtuggI"
    oauth2client.getToken code, (err, tokens) ->
      if err?
        logger.error err
        return
      oauth2client.credentials = tokens
      callback()


  getPurchaseInfo = (client, authClient, token, callback) ->
    if authClient.credentials?
      client.androidpublisher.inapppurchases.get({ packageName: "com.twofours.surespot", productId: "voice_messaging", token: token }).withAuthClient(authClient).execute(callback)

  #purchase handling
  validateVoiceToken = (username, token) ->
    return unless username? and token?

    #get validation flag for this voice message token
    rc.hget "t", "v:vm:#{token}", (err, valid) ->
      if err?
        logger.error err
        return

      unless valid is "true"
        logger.debug "validatingVoiceToken, username: #{username}, token: #{token}"
        #check token with google
        googleapis.discover("androidpublisher", "v1.1").execute (err, client) ->
          return if err?

          checkClient = (callback) ->
            if not oauth2Client?
              oauth2Client = new googleapis.OAuth2Client googleClientId, googleClientSecret, googleRedirectUrl
              getAccessToken oauth2Client, callback
            else
              callback()

          checkClient ->
            getPurchaseInfo client, oauth2Client, token, (err, data) ->
              if err?
                logger.error err
                return
              return unless data?.purchaseState?
              logger.debug "validated voice_messaging purchase token #{token}"
              rc.hset "t", "v:vm:#{token}", if data.purchaseState is 0 then "true" else "false"


  updatePurchaseTokens = (username, purchaseTokens) ->
    voiceToken = purchaseTokens.voice_messaging ? null

    #if we have something to update, update, otherwise wipe
    userKey = "u:#{username}"
    multi = rc.multi()
    #single floating license implementation
    #map username to token

    #if we have a voice token assign it to the user and the user to it
    updateLicense = (callback) ->
      if voiceToken?
        #get current user with token
        rc.hget "t", "u:vm:#{voiceToken}", (err, currentuser) ->
          return if err?
          #if user is different remove from previous user and update mappings
          if username != currentuser
            if currentuser?
              multi.hdel "u:#{currentuser}", "vm"
            multi.hset userKey, "vm", voiceToken
            multi.hset "t", "u:vm:#{voiceToken}", username
            callback()
          else
            callback()
      else
        #delete token from user
        multi.hdel userKey, "vm"
        callback()

    updateLicense ->
      #map token to username
      multi.exec (err, results) ->
        return if err?

        #validate token with google and set on return
        if voiceToken?
          validateVoiceToken username, voiceToken

  updatePurchaseTokensMiddleware = (req, res, next) ->
    return next() unless req.body?.purchaseTokens?
    logger.debug "received purchaseTokens #{req.body.purchaseTokens}"
    purchaseTokens = null
    try
      purchaseTokens = JSON.parse req.body.purchaseTokens
      updatePurchaseTokens(req.user.username, purchaseTokens)
      next()
    catch error
      next()



  hasValidVoiceMessageToken = (username, callback) ->
    rc.hget "u:#{username}", "vm", (err, token) ->
      return callback err if err?
      return callback null, false unless token?

      rc.hget "t", "v:vm:#{token}", (err, valid) ->
        return callback err if err?
        return callback null, valid is "true"


  app.post "/updatePurchaseTokens", ensureAuthenticated, (req, res, next) ->
    return res.send 400 unless req.body.purchaseTokens?
    logger.debug "received purchaseTokens #{req.body.purchaseTokens}"
    purchaseTokens = null
    try
      purchaseTokens = JSON.parse req.body.purchaseTokens
    catch error
     return next error

    return res.send 400 unless purchaseTokens?

    updatePurchaseTokens(req.user.username, purchaseTokens)
    res.send 204


  removeRoomMessage = (room, id, fn) ->
    #remove message data from set of room messages
    rc.zremrangebyscore "m:" + room, id, id, fn

  removeMessage = (to, room, id, multi, fn) ->
    user = getOtherUser room, to

    multi = rc.multi() unless multi?
    #remove message data from set of room messages
    multi.zremrangebyscore "m:" + room, id, id

    #remove from other user's deleted messages set
    multi.srem "d:#{to}:#{room}", id

    #remove from my total message pointer set
    multi.zrem "m:#{user}", "m:#{room}:#{id}"

    multi.exec fn

  filterDeletedMessages = (username, room, messages, callback) ->
    rc.smembers "d:#{username}:#{room}", (err, deleted) ->
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
          return callback err if err?
          callback null, sendMessages)

  getAllMessages = (room, fn) ->
    rc.zrange "m:#{room}", 0, -1, fn


  getMessages = (username, room, count, fn) ->
    #return last x messages
    #args = []
    rc.zrange "m:#{room}", -count, -1, 'withscores', (err, data) ->
      return fn err if err?
      filterDeletedMessages username, room, data, fn

  getControlMessages = (room, count, fn) ->
    rc.zrange "cm:" + room, -count, -1, fn

  getUserControlMessages = (user, count, fn) ->
    rc.zrange "cu:" + user, -count, -1, fn

  getMessagesAfterId = (username, room, id, fn) ->
    if id is -1
      fn null, null
    else
      if id is 0
        getMessages username, room, 30, fn
      else
        #args = []
        rc.zrangebyscore "m:#{room}", "(" + id, "+inf", 'withscores', (err, data) ->
          filterDeletedMessages username, room, data, fn

  getMessagesBeforeId = (username, room, id, fn) ->
    rc.zrangebyscore "m:#{room}", id - 60, "(" + id, 'withscores', (err, data) ->
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
        rc.zrangebyscore "cm:" + room, "(" + id, "+inf", fn

  getUserControlMessagesAfterId = (user, id, fn) ->
    if id is -1
      fn null, null
    else
      if id is 0
        getUserControlMessages user, 20, fn
      else
        rc.zrangebyscore "cu:" + user, "(" + id, "+inf", fn


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
    rc.incr "m:#{room}:id", (err, newId) ->
      if err?
        logger.error "ERROR: getNextMessageId, room: #{room}, error: #{err}"
        callback null
      else
        callback newId

  getNextMessageControlId = (room, callback) ->
    #INCR message id
    rc.incr "cm:#{room}:id", (err, newId) ->
      if err?
        logger.error "ERROR: getNextMessageControlId, room: #{room}, error: #{err}"
        callback null
      else
        callback newId

  getNextUserControlId = (user, callback) ->
          #INCR message id
    rc.incr "cu:#{user}:id", (err, newId) ->
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


  createAndSendMessage = (from, fromVersion, to, toVersion, iv, data, mimeType, id, dataSize, callback) ->
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
    message.dataSize = dataSize if dataSize
    room = getRoomName(from,to)


    #INCR message id
    getNextMessageId room, id, (id) ->
      return callback new MessageError(iv, 500) unless id?
      message.id = id

      logger.info "#{from}->#{to}, mimeType: #{mimeType}"
      newMessage = JSON.stringify(message)

      #store messages in sorted sets
      multi = rc.multi()

      userMessagesKey = "m:#{from}"
      multi.zadd "m:#{room}", id, newMessage
      #keep track of all the users message so we can remove the earliest when we cross their threshold
      #we use a sorted set here so we can easily remove when message is deleted O(N) vs O(M*log(N))
      multi.zadd userMessagesKey, time, "m:#{room}:#{id}"

      #make sure conversation is present
      multi.sadd "c:" + from, room
      multi.sadd "c:" + to, room

      #marketing wanted some stats
      #increment total user message / image counter
      switch mimeType
        when "text/plain"
          multi.hincrby "u:#{from}", "mc", 1
          multi.incr "tmc"

        when "image/"
          multi.hincrby "u:#{from}", "ic", 1
          multi.incr "tic"

        when "audio/mp4"
          multi.hincrby "u:#{from}", "vc", 1
          multi.incr "tvc"





      deleteEarliestMessage = (callback) ->
        #check how many messages the user has total
        rc.zcard userMessagesKey, (err, card) ->
          return callback err if err?
          #TODO per user threshold based on pay status
          #delete the oldest message(s)
          deleteCount = (card - MESSAGES_PER_USER) + 1
          logger.debug "deleteCount #{deleteCount}"
          if deleteCount > 0

            rc.zrange userMessagesKey,  0, deleteCount-1, (err, messagePointers) ->
              return callback err if err?
              myDeleteControlMessages = []
              theirDeleteControlMessages = []
              async.each(
                messagePointers,
                (item, callback) ->
                  messageData = getMessagePointerData from, item


                  #if the message we deleted is not part of the same conversation,send a control message
                  deletedSpot = getRoomName messageData.from, messageData.to
                  deletedFromSameSpot = room is deletedSpot

                  deleteMessage from, messageData.to, messageData.id, not deletedFromSameSpot, multi, (err, deleteControlMessage) ->
                    if not err? and deleteControlMessage?
                      myDeleteControlMessages.push deleteControlMessage

                      #don't send control message to other user in the message if it pertains to a different conversation
                      if deletedFromSameSpot
                        theirDeleteControlMessages.push deleteControlMessage


                    callback()
                (err) ->
                  logger.warn "error getting old messages to delete: #{err}" if err?
                  callback null, myDeleteControlMessages, theirDeleteControlMessages)

          else
            callback null, null

      deleteEarliestMessage (err, myDeleteControlMessages, theirDeleteControlMessages) ->
        return callback err if err?

        multi.exec  (err, results) ->
          if err?
            logger.error ("ERROR: Socket.io onmessage, " + err)
            return callback new MessageError(iv, 500)

          myMessage = null
          theirMessage = null

          #if we deleted messages, add the delete control message(s) to this message to save sending the delete control message separately
          if myDeleteControlMessages?.length > 0
            message.deleteControlMessages = myDeleteControlMessages
            myMessage = JSON.stringify message
          else
            myMessage = newMessage

          if theirDeleteControlMessages?.length > 0
            message.deleteControlMessages = theirDeleteControlMessages
            theirMessage = JSON.stringify message
          else
            theirMessage = newMessage

          sendGcm = (gcmCallback) ->
            #send gcm message
            userKey = "u:" + to
            rc.hget userKey, "gcmId", (err, gcm_id) ->
              if err?
                logger.error "error getting gcm id for user: #{to}, error: #{err}"
                return gcmCallback()

              if gcm_id?.length > 0
                logger.debug "sending gcm message"
                gcmmessage = new gcm.Message()
                sender = new gcm.Sender("#{googleApiKey}")
                gcmmessage.addData("type", "message")
                gcmmessage.addData("to", message.to)
                gcmmessage.addData("sentfrom", message.from)
                gcmmessage.addData("mimeType", message.mimeType)
                #pop entire message into gcm message if it's small enough
                if theirMessage.length <= 3800
                  gcmmessage.addData("message", theirMessage)

                gcmmessage.delayWhileIdle = false
                gcmmessage.timeToLive = GCM_TTL
                #gcmmessage.collapseKey = "message:#{getRoomName(message.from, message.to)}"
                regIds = [gcm_id]

                sender.send gcmmessage, regIds, 4, (err, result) ->
                  logger.debug "sendGcm result: #{JSON.stringify(result)}"
                  gcmCallback()
              else
                logger.debug "no gcm id for #{to}"
                gcmCallback()


          sendGcm () ->

            sio.sockets.to(to).emit "message", theirMessage
            sio.sockets.to(from).emit "message", myMessage

            callback()


  getMessagePointerData = (from, messagePointer) ->
    #delete message
    messageData = messagePointer.split(":")
    data = {}
    data.id =  messageData[3]
    room =  messageData[1] + ":" + messageData[2]
    data.to = getOtherUser room, from
    return data



  createMessageControlMessage = (from, to, room, action, data, moredata, callback)  ->
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
      controlMessageKey = "cm:#{room}"
      multi = rc.multi()

      deleteEarliestControlMessage = (callback) ->
        #check how many control messages the user has total
        rc.zcard controlMessageKey, (err, card) ->
          return callback err if err?
          #delete the oldest control message(s)
          deleteCount = (card - CONTROL_MESSAGE_HISTORY) + 1
          logger.debug "control message deleteCount #{deleteCount}"
          multi.zremrangebyrank controlMessageKey, 0, deleteCount-1 if deleteCount > 0
          callback()


      deleteEarliestControlMessage (err) ->
        logger.warn "delete earliest control message error: #{err}" if err?
        multi.zadd "cm:#{room}", id, sMessage
        multi.exec (err, results) ->
          return callback err if err?
          callback null, sMessage


  createAndSendMessageControlMessage = (from, to, room, action, data, moredata, callback) ->
    createMessageControlMessage from, to, room, action, data, moredata, (err, message) ->
      return callback err if err?
      sio.sockets.to(to).emit "control", message
      callback null, message

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

        multi = rc.multi()
        controlMessageKey = "cu:#{to}"

        deleteEarliestControlMessage = (callback) ->
          #check how many control messages the user has total
          rc.zcard controlMessageKey, (err, card) ->
            return callback err if err?
            #delete the oldest control message(s)
            deleteCount = (card - CONTROL_MESSAGE_HISTORY) + 1
            logger.debug "user control message deleteCount: #{deleteCount}"
            multi.zremrangebyrank controlMessageKey, 0, deleteCount-1 if deleteCount > 0
            callback()


        deleteEarliestControlMessage (err) ->

          multi.zadd controlMessageKey, id, newMessage
          multi.exec (err, results) ->
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
      rc.smembers "c:#{who}", (err, convos) ->
        return callback err if err?
        async.each convos, (room, callback) ->
          to = getOtherUser(room, who)
          createAndSendUserControlMessage to, "revoke", who, newVersion, (err) ->
            logger.error ("ERROR: adding user control message, " + err) if err?
            return callback new error 'could not send user controlmessage' if err?
            callback()
        , callback


  handleMessages = (socket, user, data) ->
    #rate limit
    if RATE_LIMITING_MESSAGE
      ratelimitermessages.add user
      ratelimitermessages.count user, RATE_LIMIT_SECS_MESSAGE, (err,requests) ->

        if requests > RATE_LIMIT_RATE_MESSAGE
          ip = client.handshake.headers['x-forwarded-for'] or client.handshake.address.address
          logger.warn "rate limiting messages for user: #{user}, ip: #{ip}"
          try
            message = JSON.parse(data)

            if typeIsArray message
              #todo  this blows but will do for now
              #would be better to send bulk messages on a separate event but fuck it
              return socket.emit "messageError", new MessageError(data, 429)
            else
              return socket.emit "messageError", new MessageError(message.iv, 429)
          catch error
            return socket.emit "messageError", new MessageError(data, 500)



    message = undefined
    #todo check from and to exist and are friends
    try
      message = JSON.parse(data)
    catch error
      return callback new MessageError(data, 500)

    if typeIsArray message
      async.each(
        message,
        (item, callback) ->
          handleSingleMessage user, item, (err) ->
            socket.emit "messageError", err if err?
            callback()
        (err) -> )

    else
      handleSingleMessage user, message, (err) ->
        socket.emit "messageError", err if err?


  handleSingleMessage = (user, message, callback) ->
    # message.user = user
    logger.debug "received message from user #{user}"

    iv = message.iv
    return callback new MessageError(user, 400) unless iv?
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
            room = getRoomName(from, to)

            mimeType = message.mimeType
            #todo validate mimetype


            #check for dupes if message has been resent
            checkForDuplicateMessage resendId, user, room, message, (err, found) ->
              return callback new MessageError(iv, 500) if err?
              if found
                logger.debug "found duplicate message, not adding to db"
                sio.sockets.to(to).emit "message", found
                sio.sockets.to(from).emit "message", found
                callback()
              else
                createAndSendMessage from, fromVersion, to, toVersion, iv, cipherdata, mimeType, null, null, callback


  sio.on "connection", (socket) ->
    user = socket.handshake.session.passport.user

    rc.incr "socketCount", (err, count) ->
      #join user's room
      logger.info "#{user} connected: #{count}"

    socket.join user

    socket.on "message", (data) -> handleMessages socket, user, data
    socket.on "disconnect", ->
      rc.decr "socketCount", (err, count) ->
        #join user's room
        logger.info "#{user} disconnected: #{count}"



  #delete all messages
  app.delete "/messagesutai/:username/:id", ensureAuthenticated, validateUsernameExistsOrDeleted, validateAreFriendsOrDeleted, (req, res, next) ->

    username = req.user.username
    otherUser = req.params.username
    room = getRoomName username, otherUser
    id = req.params.id

    return res.send 400 unless id?

    logger.debug "deleting messages, user: #{username}, otherUser: #{otherUser}, utaiId: #{id}"
    deleteAllMessages username, otherUser, id, (err) ->
      return next err if err?
      res.send 204


  deleteAllMessages = (username, otherUser, utaiId, callback) ->
    room = getRoomName username, otherUser
    getAllMessages room, (err, messages) ->
      return callback err if err?

      lastMessageId = null
      if messages?.length > 0
        lastMessageId = JSON.parse(messages[messages.length-1]).id
        logger.debug "lastMessageId: #{lastMessageId}"
        #client could have passed anything in, dooming us for eternity, don't let this happen
        if utaiId > lastMessageId
          logger.debug "setting utaiId to lastMessageId: #{lastMessageId}"
          utaiId = lastMessageId
      else
        return callback()


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

          #don't delete newer messages than specified
          return callback false if oMessage.id > utaiId

          if oMessage.from is username
            ourMessageIds.push oMessage.id
            multi.zrem "m:#{username}", "m:#{room}:#{oMessage.id}"

            #delete image from rackspace
            if oMessage.mimeType is 'image/' or oMessage.mimeType is 'audio/mp4'
              deleteImage oMessage.data

            callback true
          else
            theirMessageIds.push oMessage.id
            callback false
        (results) ->

          if ourMessageIds.length > 0
            #zrem does not handle array as last parameter https://github.com/mranney/node_redis/issues/404
            results.unshift "m:#{room}"
            #need z remove by score here :( http://redis.io/commands/zrem#comment-845220154
            #remove the messages
            multi.zrem results
            #remove deleted message ids from other user's deleted set as the message is gone now
            multi.srem "d:#{otherUser}:#{room}", ourMessageIds
            #remove message pointers


          #todo remove the associated control messages

          if theirMessageIds.length > 0
            #add their message id's to our deleted message set
            multi.sadd "d:#{username}:#{room}", theirMessageIds


          multi.exec (err, mResults) ->
            return callback err if err?
            createAndSendMessageControlMessage username, otherUser, room, "deleteAll", room, lastMessageId, (err) ->
              return callback err if err?
              callback())


  deleteMessage = (from, to, messageId, sendControlMessage, multi, callback) ->
    room = getRoomName to, from
    #get the message we're modifying
    getMessage room, messageId, (err, dMessage) ->
      return callback err if err?
      return callback null, null unless dMessage?

      deleteMessageInternal = (callback) ->
        #if we sent it, delete the data
        if (from is dMessage.from)

          #update message data
          removeMessage dMessage.to, room, messageId, multi, (err, count) ->
            return callback err if err?

            #delete the file if it's a file
            if dMessage.mimeType is "image/" or dMessage.mimeType is 'audio/mp4'
              deleteImage dMessage.data

            callback()
        else
          #check if user is a user (ie. not deleted) before adding deleted message ids to the set
          rc.sismember "u", from, (err, isUser) ->
            return callback err if err?

            if isUser
              rc.sadd "d:#{from}:#{room}", messageId, (err, count) ->
                return callback err if err?
                callback()
            else
                callback()

      deleteMessageInternal (err) ->
        return callback err if err?
        if (sendControlMessage)
          createAndSendMessageControlMessage from, to, room, "delete", room, messageId, (err, message) ->
            return callback err if err?
            callback null, message
        else
          createMessageControlMessage from, to, room, "delete", room, messageId, (err, message) ->
            return callback err if err?
            callback null, message



  deleteImage = (uri) ->
    splits = uri.split('/')
    path = splits[splits.length - 1]
    logger.debug "removing file from rackspace: #{path}"
    rackspace.removeFile rackspaceImageContainer, path, (err) ->
      if err?
        logger.error "could not remove file from rackspace: #{path}, error: #{err}"
      else
        logger.debug "removed file from rackspace: #{path}"






  #delete single message
  app.delete "/messages/:username/:id", ensureAuthenticated, validateUsernameExistsOrDeleted, validateAreFriendsOrDeleted, (req, res, next) ->

    messageId = req.params.id
    return next new Error 'id required' unless messageId?

    username = req.user.username
    otherUser = req.params.username

    deleteMessage username, otherUser, messageId, true, null, (err, deleteControlMessage) ->
      return next err if err?
      res.send (if deleteControlMessage? then 204 else 404)

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

      generateSecureRandomBytes 'base64', (err, token) ->
        return next err if err?
        rc.set "dt:#{username}", token, (err, result) ->
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

      generateSecureRandomBytes 'base64', (err, token) ->
        return next err if err?
        rc.set "pt:#{username}", token, (err, result) ->
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
        rc.zadd "m:#{room}", messageId, JSON.stringify(dMessage), (err, addcount) ->
          return next err if err?
          createAndSendMessageControlMessage username, otherUser, room, (if bShareable then "shareable" else "notshareable"), room, messageId, (err) ->
            return next err if err?
            res.send 204


  app.post "/images/:username/:version", ensureAuthenticated, validateUsernameExists, validateAreFriends, (req, res, next) ->

    username = req.user.username
    otherUser = req.params.username
    version = req.params.version

    form = new formidable.IncomingForm()
    form.onPart = (part) ->
      return form.handlePart part unless part.filename?
      iv = part.filename

      outStream = new rstream.PassThrough()

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

      #no need for secure randoms for image paths
      generateRandomBytes 'hex', (err, bytes) ->
        return next err if err?

        path = bytes
        logger.debug "received part: #{part.filename}, uploading to rackspace at: #{path}"

        outStream.pipe rackspace.upload {container: rackspaceImageContainer, remote: path}, (err) ->
          if err?
            logger.error "POST /images/:username/:version, error: #{err}"
            return next err #delete filenames[part.filename]

          logger.debug 'upload completed'
          url = rackspaceCdnBaseUrl + "/#{path}"

          getFriendImageData username, otherUser, (err, friend) ->
            return next err if err?

            if friend.imageUrl?
              deleteImage friend.imageUrl

            rc.hmset "fi:#{username}", "#{otherUser}:imageUrl", url, "#{otherUser}:imageVersion", version, "#{otherUser}:imageIv", iv, (err, status) ->
              return next err if err?
              res.send url

    form.on 'error', (err) ->
      next new Error err

    form.parse req

  #doing more than images now, don't feel like changing the api though..yet
  app.post "/images/:fromversion/:username/:toversion", ensureAuthenticated, validateUsernameExists, validateAreFriends, (req, res, next) ->
    #upload image to rackspace then create a message with the image url and send it to chat recipients
    username = req.user.username
    path = null
    size = null

    form = new formidable.IncomingForm()
    form.onPart = (part) ->
      return form.handlePart part unless part.filename?
    #  filenames[part.filename] = "uploading"
      iv = part.filename
      mimeType = part.mime

      #check valid mimetypes
      return res.send 400 unless mimeType in ['text/plain', 'image/','audio/mp4']


      checkPermissions = (callback) ->
        #if it's audio make sure we have permission
        if mimeType is "audio/mp4"
          hasValidVoiceMessageToken username, (err, valid) ->
            return next err if err?
            #yes it's a 402
            return res.send 402 if not valid
            callback()
        else
          callback()


      checkPermissions ->


        #todo validate versions

        outStream = new rstream.PassThrough()


        part.on 'data', (buffer) ->
          form.pause()

          size += buffer.length
          #logger.debug "received file data, length: #{buffer.length}, size: #{size}"
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
            err = new Error 'could not generate messageId'
            logger.error "fileupload, mimeType: #{mimeType} error: #{err}"
            #sio.sockets.to(username).emit "messageError", new MessageError(iv, 500)
            return next err # delete filenames[part.filename]

          #no need for secure randoms for image paths
          generateRandomBytes 'hex', (err, bytes) ->
            if err?
              logger.error "fileupload, mimeType: #{mimeType} error: #{err}"
              #sio.sockets.to(username).emit "messageError", new MessageError(iv, 500)
              return next err #delete filenames[part.filename]

            path = bytes
            logger.debug "received part: #{part.filename}, uploading to rackspace at: #{path}"

            outStream.pipe rackspace.upload {container: rackspaceImageContainer, remote: path}, (err) ->
              if err?
                logger.error "fileupload, mimeType: #{mimeType} error: #{err}"
                #sio.sockets.to(username).emit "messageError", new MessageError(iv, 500)
                return next err #delete filenames[part.filename]

              logger.debug "upload completed #{path}, size: #{size}"
              uri = rackspaceCdnBaseUrl + "/#{path}"
              #uris.push uri
              createAndSendMessage req.user.username, req.params.fromversion, req.params.username, req.params.toversion, part.filename, uri, mimeType, id, size, (err) ->
                logger.error "error sending message on socket: #{err}" if err?
                return next err if err?
                res.send 200

    form.on 'error', (err) ->
      next new Error err

    form.on 'end', ->
      logger.debug "form end #{path}"
      #res.send 200

    form.parse req


  getConversationIds = (username, callback) ->
    rc.smembers "c:" + username, (err, conversations) ->
      return callback err if err?
      if (conversations.length > 0)
        conversationsWithId = _.map conversations, (conversation) -> "m:#{conversation}:id"
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
            controlIdKeys.push "cm:#{item.conversation}:id"
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


  #get remote messages before id
  app.get "/messages/:username/before/:messageid", ensureAuthenticated, validateUsernameExistsOrDeleted, validateAreFriendsOrDeleted, setNoCache, (req, res, next) ->
    #return messages since id
    getMessagesBeforeId req.user.username, getRoomName(req.user.username, req.params.username), req.params.messageid, (err, data) ->
      return next err if err?
      res.send data

  app.get "/messagedata/:username/:messageid/:controlmessageid", ensureAuthenticated, validateUsernameExistsOrDeleted, validateAreFriendsOrDeleted, setNoCache, (req, res, next) ->
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

  app.get "/publickeys/:username", ensureAuthenticated, validateUsernameExistsOrDeleted, validateAreFriendsOrDeleted, setNoCache, getPublicKeys
  app.get "/publickeys/:username/:version", ensureAuthenticated, validateUsernameExistsOrDeleted, validateAreFriendsOrDeleted, setCache(oneYear), getPublicKeys
  app.get "/keyversion/:username", ensureAuthenticated, validateUsernameExistsOrDeleted, validateAreFriendsOrDeleted,(req, res, next) ->
    rc.get "kv:#{req.params.username}", (err, version) ->
      return next err if err?
      res.send version

  handleReferrers = (username, referrers, callback) ->
    return callback() if referrers.length is 0
    usersToInvite = []
    multi = rc.multi()
    async.each(
      referrers,
      (referrer, callback) ->
        referralUserName = referrer.utm_content
        referralSource = referrer.utm_medium
        usersToInvite.push { username: referralUserName, source: referralSource }
        multi.sismember "u", referralUserName
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
                ref = usersToInvite[index]
                inviteUser username, ref.username, ref.source, (err, inviteSent) ->
                  logger.error "handleReferrers, error: #{err}" if err?
          )
          callback())


  #they didn't have surespot on their phone so they came here so direct them to the play store
  app.get "/autoinvite/:username/:source", validateUsernameExists, (req, res, next) ->
    username = req.params.username
    source = req.params.source

    redirectUrl = "market://details?id=com.twofours.surespot&referrer="
    query = "utm_source=surespot_android&utm_medium=#{source}&utm_content=#{username}"

    res.redirect  redirectUrl + encodeURIComponent(query)

  createNewUser = (req, res, next) ->
    username = req.body.username
    password = req.body.password
    version = req.body.version

    logger.debug "version: #{version}"
    #return next new Error('username required') unless username?
    #return next new Error('password required') unless password?

    userExistsOrDeleted username, true, (err, exists) ->
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
            logger.error "createNewUser, error: #{error}"
            return next error


        logger.debug "gcmID: #{user.gcmId}"
        logger.debug "referrers: #{req.body.referrers}"

        bcrypt.genSalt 10, 32, (err, salt) ->
          return next err if err?
          bcrypt.hash password, salt, (err, password) ->
            return next err if err?
            user.password = password

            #sign the keys
            keys.dhPubSig = crypto.createSign('sha256').update(new Buffer(keys.dhPub)).sign(serverPrivateKey, 'base64')
            keys.dsaPubSig = crypto.createSign('sha256').update(new Buffer(keys.dsaPub)).sign(serverPrivateKey, 'base64')
            logger.debug "#{username}, dhPubSig: #{keys.dhPubSig}, dsaPubSig: #{keys.dsaPubSig}"

            multi2 = rc.multi()
            #user id
            multi2.incr "uid"
            #get key version
            multi2.incr "kv:#{username}"
            multi2.exec (err, results) ->
              return next err if err?

              user.id = results[0]
              kv = results[1]

              multi = rc.multi()
              userKey = "u:#{username}"
              keysKey = "k:#{username}"
              keys.version = kv + ""
              multi.hmset userKey, user
              multi.hset keysKey, kv, JSON.stringify(keys)
              multi.sadd "u", username
              multi.exec (err,replies) ->
                return next err if err?
                logger.info "#{username} created, uid: #{user.id}"
                req.login user, ->
                  req.user = user
                  if referrers
                    handleReferrers username, referrers, next
                  else
                    next()





  rateLimitByIp = (limit, limiter, seconds, rate) -> (req, res, next) ->
    return next() unless limit

    ip = req.header('x-forwarded-for') or req.connection.remoteAddress
    #port = req.connection.remotePort

    #if we use this before stream we need to pause req

    #hash the ip, no data is associated so doesn't really need to be secure, also ip address + port is 48 bit range so don't need crazy hashing function
    hash = crypto.createHash('md4').update(ip).digest('base64')
    logger.debug "checking rate limiting, hash: #{hash}, seconds: #{seconds}, rate: #{rate}"

    limiter.add hash
    limiter.count hash, seconds, (err, requests) ->
      return next err if err?
      if requests > rate
        username = req.body.username
        logger.warn "rate limiting ip: #{ip}" + if username? then ", user: #{username}" else "" #", port #{port}"
        return res.send 429
      else
        next()



  # unauth'd methods have rate limit
  app.head "/ping", rateLimitByIp(RATE_LIMITING_PING, ratelimiterping, RATE_LIMIT_SECS_PING, RATE_LIMIT_RATE_PING), (req,res,next) ->
    rc.time (err, time) ->
      return next err if err?
      return next new Error 'redis does not know what time it is' unless time
      res.send 204

  app.get "/users/:username/exists", rateLimitByIp(RATE_LIMITING_EXISTS, ratelimiterexists, RATE_LIMIT_SECS_EXISTS, RATE_LIMIT_RATE_EXISTS), setNoCache, (req, res, next) ->
    userExistsOrDeleted req.params.username, true, (err, exists) ->
      return next err if err?
      res.send exists



  validateVersion = (req, res, next) ->
    version = req.body.version ? "not sent"
    logger.debug "validate version: #{version}"
    #reserved for future use, will send 403 if version is not acceptable
    #res.send 403
    next()

  app.post "/users",
    validateVersion,
    validateUsernamePassword,
    rateLimitByIp(RATE_LIMITING_CREATE_USER, ratelimitercreateuser, RATE_LIMIT_SECS_CREATE_USER, RATE_LIMIT_RATE_CREATE_USER),
    createNewUser,
    passport.authenticate("local"),
    updatePurchaseTokensMiddleware,
    (req, res, next) ->
      res.send 201




  #end unauth'd methods




  app.post "/login", passport.authenticate("local"), validateVersion, updatePurchaseTokensMiddleware, (req, res, next) ->
    username = req.user.username

    logger.debug "/login post, user #{username}"

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
      rc.get "kv:#{username}", (err, currkv) ->
        return next err if err?

        #inc key version
        kv = parseInt(currkv) + 1
        generateSecureRandomBytes 'base64',(err, token) ->
          return next err if err?
          rc.set "kt:#{username}", token, (err, result) ->
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
    rc.get "kv:#{username}", (err, storedkv) ->
      return next err if err?

      storedkv++
      return next new Error 'key versions do not match' unless storedkv is parseInt(kv)

      #todo transaction
      #make sure the tokens match
      rc.get "kt:#{username}", (err, rtoken) ->
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
            rc.del "kt:#{username}", (err, rdel) ->
              return next err if err?
              return res.send 404 unless rdel is 1

              #sign the keys
              newKeys.dhPubSig = crypto.createSign('sha256').update(new Buffer(newKeys.dhPub)).sign(serverPrivateKey, 'base64')
              newKeys.dsaPubSig = crypto.createSign('sha256').update(new Buffer(newKeys.dsaPub)).sign(serverPrivateKey, 'base64')
              logger.debug "saving keys #{username}, dhPubSig: #{newKeys.dhPubSig}, dsaPubSig: #{newKeys.dsaPubSig}"

              keysKey = "k:#{username}"
              newKeys.version = storedkv + ""
              #add the keys to the key set and add revoke message in transaction
              multi = rc.multi()
              multi.hset keysKey, kv, JSON.stringify(newKeys)
              #update the version
              multi.set "kv:#{username}", storedkv

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
    userKey = "u:#{req.user.username}"
    rc.hset userKey, "gcmId", gcmId, (err) ->
      return next err if err?
      res.send 204


  inviteUser = (username, friendname, source, callback) ->
    #keep running count of autoinvites
    if source?
      logger.info "#{username} invited #{friendname} via #{source}"
      rc.hincrby "ai", source, 1


    multi = rc.multi()
    #remove you from my blocked set if you're blocked
    multi.srem "b:#{username}", friendname
    multi.sadd "is:#{username}", friendname
    multi.sadd "ir:#{friendname}", username
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
            userKey = "u:" + friendname
            rc.hget userKey, "gcmId", (err, gcmId) ->
              if err?
                logger.error "inviteUser, " + err
                return callback new Error err

              if gcmId?.length > 0
                logger.debug "sending gcm notification"
                gcmmessage = new gcm.Message()
                sender = new gcm.Sender("#{googleApiKey}")
                gcmmessage.addData "type", "invite"
                gcmmessage.addData "sentfrom", username
                gcmmessage.addData "to", friendname
                gcmmessage.delayWhileIdle = false
                gcmmessage.timeToLive = GCM_TTL
                #gcmmessage.collapseKey = "invite:#{friendname}"
                regIds = [gcmId]

                sender.send gcmmessage, regIds, 4, (err, result) ->
                  logger.debug "sent gcm: #{JSON.stringify(result)}"
                  callback null, true
              else
                logger.debug "gcmId not set for #{friendname}"
                callback null, true
      else
        callback null, false



  handleInvite = (req,res,next) ->
    friendname = req.params.username
    username = req.user.username
    source = req.params.source ? "manual"

    # the caller wants to add himself as a friend
    if friendname is username then return res.send 403

    logger.debug "#{username} inviting #{friendname} to be friends"

    multi = rc.multi()
    #check if friendname has blocked username - 404
    multi.sismember "b:#{friendname}", username

    #if he's deleted me then 404
    multi.sismember "ud:#{username}", friendname

    #if i've previously deleted the user and I invite him now then unmark me as deleted to him
    #multi.srem "ud:#{friendname}", username

    multi.exec (err, results) ->
      return next err if err?
      return res.send 404 if 1 in [results[0],results[1]]

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
              inviteUser username, friendname, source, (err, inviteSent) ->
                res.send if inviteSent then 204 else 403


  app.post "/invite/:username/:source", ensureAuthenticated, validateUsernameExists, handleInvite
  app.post "/invite/:username", ensureAuthenticated, validateUsernameExists, handleInvite


  createFriendShip = (username, friendname, callback) ->
    multi = rc.multi()
    multi.sadd "f:#{username}", friendname
    multi.sadd "f:#{friendname}", username
    multi.srem "ud:#{username}", friendname
    multi.srem "ud:#{friendname}", username
    multi.exec (err, results) ->
      return callback new Error("createFriendShip failed for username: " + username + ", friendname" + friendname) if err?
      createAndSendUserControlMessage username, "added", friendname, null, (err) ->
        return callback err if err?
        createAndSendUserControlMessage friendname, "added", username, null, (err) ->
          return callback err if err?
          callback null

  deleteInvites = (username, friendname, callback) ->
    multi = rc.multi()
    multi.srem "ir:#{username}", friendname
    multi.srem "is:#{friendname}", username
    multi.exec (err, results) ->
      return callback new Error("[friend] srem failed for ir:#{username}:#{friendname}") if err?
      callback null

  sendInviteResponseGcm = (username, friendname, action, callback) ->
    userKey = "u:" + friendname
    rc.hget userKey, "gcmId", (err, gcmId) ->
      if err?
        logger.error "sendInviteResponseGcm, #{err}"
        return next new Error err

      if gcmId?.length > 0
        logger.debug "sending gcm invite response notification"

        gcmmessage = new gcm.Message()
        sender = new gcm.Sender("#{googleApiKey}")
        gcmmessage.addData("type", "inviteResponse")
        gcmmessage.addData "sentfrom", username
        gcmmessage.addData "to", friendname
        gcmmessage.addData("response", action)
        gcmmessage.delayWhileIdle = false
        gcmmessage.timeToLive = GCM_TTL
        #gcmmessage.collapseKey = "inviteResponse"
        regIds = [gcmId]

        sender.send gcmmessage, regIds, 4, (err, result) ->
          logger.debug "sendGcm result: #{JSON.stringify(result)}"
          callback result
      else
          callback null

  app.post '/invites/:username/:action', ensureAuthenticated, validateUsernameExists, (req, res, next) ->
    return next new Error 'action required' unless req.params.action?


    username = req.user.username
    friendname = req.params.username
    action = req.params.action

    logger.info "#{username} #{action} #{friendname}"

    #make sure invite exists
    inviteExists friendname, username, (err, result) ->
      return next err if err?
      return res.send 404 if not result

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
            rc.sadd "b:#{username}", friendname, (err, data) ->
              return next err if err?
              createAndSendUserControlMessage friendname, 'ignore', username, null, (err) ->
                return next err if err?
                createAndSendUserControlMessage username, 'ignore', username, null, (err) ->
                  return next err if err?
                  res.send 204

          else return next new Error 'invalid action'


  getFriendImageData = (username, friendname, callback) ->
    rc.hmget "fi:#{username}", "#{friendname}:imageUrl", "#{friendname}:imageVersion", "#{friendname}:imageIv", (err, friendImageData) ->
      return callback err if err?
      callback null, new Friend friendname, 0, friendImageData[0], friendImageData[1], friendImageData[2]


  getFriends = (req, res, next) ->
    username = req.user.username
    #get users we're friends with
    rc.smembers "f:#{username}", (err, rfriends) ->
      return next err if err?
      friends = []
      return res.send {} unless rfriends?

      _.each rfriends, (name) ->
        #todo use bulk operation
        getFriendImageData username, name, (err, friend) ->
          return next err if err?
          friends.push friend

      #get users that invited us
      rc.smembers "ir:#{username}", (err, invites) ->
        return next err if err?
        _.each invites, (name) -> friends.push new Friend name, 32

        #get users that we invited
        rc.smembers "is:#{username}", (err, invited) ->
          return next err if err?
          _.each invited, (name) -> friends.push new Friend name, 2

          #get users that deleted us that we haven't deleted
          rc.smembers "ud:#{username}", (err, deleted) ->
            return next err if err?
            _.each deleted, (name) ->

              friend = friends.filter (friend) -> friend.name is name

              if friend.length is 1
                friend[0].flags += 1
              else
                friends.push new Friend name, 1



            rc.get "cu:#{username}:id", (err, id) ->
              friendstate = {}
              friendstate.userControlId = id ? 0
              friendstate.friends = friends

              sFriendState = JSON.stringify friendstate
              logger.debug ("friendstate: " + sFriendState)
              res.setHeader('Content-Type', 'application/json');
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
    rc.get "dt:#{username}", (err, rtoken) ->
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
          rc.del "dt:#{username}", (err, rdel) ->
            return next err if err?
            return res.send 404 unless rdel is 1

            multi = rc.multi()

            #delete invites
            multi.del "ir:#{username}"
            multi.del "is:#{username}"
            #tell users that invited me that i'm deleted
            #get users that invited us
            rc.smembers "ir:#{username}", (err, invites) ->
              return next err if err?
              #delete their invites
              async.each(
                invites,
                (name, callback) ->
                  multi.srem "is:#{name}", username

                  #tell them we've been deleted
                  createAndSendUserControlMessage name, "delete", username, username, (err) ->
                    #return callback err if err?
                    callback()
                (err) ->
                  return next err if err?
                  #delete my invites to them
                  rc.smembers "is:#{username}", (err, invited) ->
                    return next err if err?

                    async.each(
                      invited,
                      (name, callback) ->
                        multi.srem "ir:#{name}", username

                        #tell them we've been deleted
                        createAndSendUserControlMessage name, "delete", username, username, (err) ->
                          #return callback err if err?
                          callback()
                      (err) ->
                        return next err if err?

                        #copy data from user's list of friends to list of deleted users friends
                        rc.smembers "f:#{username}", (err, friends) ->
                          return next err if err?

                          addDeletedFriend = (friends, callback) ->
                            if friends.length > 0
                              rc.sadd "d:#{username}", friends, (err, nadded) ->
                                return next err if err?
                                callback()
                            else
                              callback()

                          addDeletedFriend friends, (err) ->
                            return next err if err?

                            #remove me from the global set of users
                            multi.srem "u", username

                            #add me to the global set of deleted users
                            multi.sadd "d", username

                            multi.del "u:#{username}"

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
                                    res.send 204)))


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
    rc.get "pt:#{username}", (err, rtoken) ->
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
          rc.del "pt:#{username}", (err, rdel) ->
            return next err if err?
            return res.send 404 unless rdel is 1

            bcrypt.genSalt 10, 32, (err, salt) ->
              return next err if err?

              bcrypt.hash newPassword, salt, (err, hashedPassword) ->
                return next err if err?
                rc.hset "u:#{username}", "password", hashedPassword, (err, set) ->
                  return next err if err?
                  res.send 204


  app.delete "/friends/:username", ensureAuthenticated, validateUsernameExistsOrDeleted, validateAreFriendsOrDeletedOrInvited, (req, res, next) ->
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
    multi.srem "d", username
    multi.del "k:#{username}"
    multi.del "kv:#{username}"
    multi.del "cu:#{username}"
    multi.del "cu:#{username}:id"


  deleteUser = (username, theirUsername, multi, next) ->
    #check if they've only been invited
    rc.sismember "is:#{username}", theirUsername, (err, isInvited) ->
      return next err if err?
      if isInvited
        deleteInvites theirUsername, username, (err) ->
          return next err if err?
          next()
      else
        room = getRoomName username, theirUsername

        #delete the conversation with this user from the set of my conversations
        multi.srem "c:#{username}", room


        getFriendImageData username, theirUsername, (err, friend) ->
          if friend.imageUrl?
            deleteImage friend.imageUrl

        multi.hdel "fi:#{username}", "#{theirUsername}:imageUrl", "#{theirUsername}:imageVersion", "#{theirUsername}:imageIv"

        #todo delete related user control messages

        #if i've been deleted by them this will be populated with their username
        rc.sismember "ud:#{username}", theirUsername, (err, theyHaveDeletedMe) ->
          return next err if err?

          #if we are deleting them and they haven't deleted us already
          if not theyHaveDeletedMe
            #delete our messages with the other user
            #get the latest id
            rc.get "m:#{room}:id", (err, id) ->
              return next err if err?
              #handle no id
              deleteMessages = (messageId, callback) ->
                if messageId?
                  deleteAllMessages username, theirUsername, id, (err) ->
                    return callback err if err?
                    callback()
                else
                  callback()

              deleteMessages id, (err) ->
                return next err if err?
                #delete friend association
                multi.srem "f:#{username}", theirUsername
                multi.srem "f:#{theirUsername}", username

                #add me to their set of deleted users if they're not deleted
                rc.sismember "d", theirUsername, (err, isDeleted) ->
                  return next err if err?
                  if not isDeleted
                    multi.sadd "ud:#{theirUsername}", username
                  next()

          #they've already deleted me
          else
            #remove them from their deleted set (if they deleted their identity) (don't use multi so we can check card post removal later)
            rc.srem "d:#{theirUsername}", username, (err, rCount) ->
              return next err if err?
              #if they have been deleted and we are the last person to delete them
              #remove the final pieces of data
              rc.sismember "d", theirUsername, (err, isDeleted) ->
                return next err if err?

                deleteLastUserScraps = (callback) ->

                  if isDeleted
                    rc.scard "d:#{theirUsername}", (err, card) ->
                      return callback err if err?
                      if card is 0
                        deleteRemainingIdentityData multi, theirUsername
                        callback()
                      else
                        callback()
                  else
                    callback()

                deleteLastUserScraps (err) ->
                  return next err if err?

                  rc.get "m:#{room}:id", (err, id) ->
                    return next err if err?
                    deleteMessages = (callback) ->
                      if id?
                        deleteAllMessages username, theirUsername, id, (err) ->
                          return callback err if err?
                          callback()
                      else
                        callback()

                    deleteMessages (err) ->
                      return next err if err?

                      #delete control message data
                      multi.del "cm:#{room}"
                      multi.del "cm:#{room}:id"

                      #remove them from my deleted set
                      multi.srem "ud:#{username}", theirUsername

                      #delete the set that held message ids of theirs that we deleted
                      multi.del "d:#{username}:#{room}"

                      #delete the set that held message ids of mine that they deleted
                      multi.del "d:#{theirUsername}:#{room}"

                      multi.del "m:#{room}:id"
                      multi.del "m:#{room}"
                      next()


  app.post "/logout", ensureAuthenticated, (req, res) ->
    logger.info "#{req.user.username} logged out"
    req.logout()
    res.send 204


  generateSecureRandomBytes = (encoding, callback) ->
    crypto.randomBytes 32, (err, bytes) ->
      return callback err if err?
      callback null, bytes.toString(encoding)

  generateRandomBytes = (encoding, callback) ->
    crypto.pseudoRandomBytes 16, (err, bytes) ->
      return callback err if err?
      callback null, bytes.toString(encoding)

  comparePassword = (password, dbpassword, callback) ->
    bcrypt.compare password, dbpassword, callback

  getLatestKeys = (username, callback) ->
    rc.get "kv:#{username}", (err, version) ->
      return callback err if err?
      return callback new Error 'no keys exist for user: #{username}' unless version?
      getKeys username, version, callback

  getKeys = (username, version, callback) ->
    rc.hget "k:#{username}", version, (err, keys) ->
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
    userKey = "u:" + username
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
    logger.debug "client ip: #{req.connection.remoteAddress}"
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
    rcs.hgetall "u:" + username, (err, user) ->
      done err, user

