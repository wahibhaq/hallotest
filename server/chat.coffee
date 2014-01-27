helenus = require 'helenus'
common = require './common'
bunyan = require 'bunyan'
pool = null

bunyanStreams = [{
  level: 'debug'
  stream: process.stdout
}]

logger = bunyan.createLogger({
  name: 'surespot'
  streams: bunyanStreams
});

exports.connect = (callback) ->
  pool = new helenus.ConnectionPool({host:'localhost', port:9160, keyspace:'surespot'});
  pool.connect (err, keyspace) ->
    if (err)
      callback err

exports.insertTextMessage = (message, callback) ->
  spot = common.getRoomName(message.from, message.to)

  cql =
  "BEGIN BATCH
  INSERT INTO chatmessages (username, spotname, id, datetime, fromuser, fromversion, touser, toversion, iv, data, mimeType)
  VALUES (?, ?, ?, ?, ?,?,?,?,?,?,? )
  INSERT INTO chatmessages (username, spotname, id, datetime, fromuser, fromversion, touser, toversion, iv, data, mimeType)
    VALUES (?, ?, ?, ?, ?,?,?,?,?,?,? )
  APPLY BATCH"

  logger.debug "sending cql #{cql}"

  pool.cql cql, [
    message.to,
    spot,
    message.id,
    message.datetime,
    message.from,
    message.fromVersion,
    message.to,
    message.toVersion,
    message.iv,
    message.data,
    message.mimeType,

    message.from,
    spot,
    message.id,
    message.datetime,
    message.from,
    message.fromVersion,
    message.to,
    message.toVersion,
    message.iv,
    message.data,
    message.mimeType
  ], callback


exports.removeRoomMessage = (room, id, fn) ->
    #remove message data from set of room messages
    rc.zremrangebyscore "m:" + room, id, id, fn

exports.removeMessage = (to, room, id, multi, fn) ->
    user = getOtherUser room, to

    multi = rc.multi() unless multi?
    #remove message data from set of room messages
    multi.zremrangebyscore "m:" + room, id, id

    #remove from other user's deleted messages set
    multi.srem "d:#{to}:#{room}", id

    #remove from my total message pointer set
    multi.zrem "m:#{user}", "m:#{room}:#{id}"

    multi.exec fn

exports.getAllMessages = (room, fn) ->
    rc.zrange "m:#{room}", 0, -1, fn


exports.getMessages = (username, room, count, fn) ->
    #return last x messages
    #args = []
    rc.zrange "m:#{room}", -count, -1, 'withscores', (err, data) ->
      return fn err if err?
      filterDeletedMessages username, room, data, fn

exports.getControlMessages = (room, count, fn) ->
    rc.zrange "cm:" + room, -count, -1, fn

exports.getUserControlMessages = (user, count, fn) ->
    rc.zrange "cu:" + user, -count, -1, fn

exports.getMessagesAfterId = (username, room, id, fn) ->
    if id is -1
      fn null, null
    else
      if id is 0
        getMessages username, room, 30, fn
      else
        #args = []
        rc.zrangebyscore "m:#{room}", "(" + id, "+inf", 'withscores', (err, data) ->
          filterDeletedMessages username, room, data, fn

exports.getMessagesBeforeId = (username, room, id, fn) ->
    rc.zrangebyscore "m:#{room}", id - 60, "(" + id, 'withscores', (err, data) ->
      filterDeletedMessages username, room, data, fn

exports.checkForDuplicateMessage = (resendId, username, room, message, callback) ->
    if (resendId?)
      if (resendId > 0)
        logger.debug "searching room: #{room} from id: #{resendId} for duplicate messages"
        #check messages client doesn't have for dupes
        getMessagesAfterId username, room, resendId, (err, data) ->
          logger.error "error getting messages" if err?
          return callback err if err
          found = _.find data, (checkMessageJSON) ->
            checkMessage = undefined
            try
              logger.debug "parsing #{checkMessageJSON}"
              checkMessage = JSON.parse(checkMessageJSON)
            catch error
              logger.debug "error parsing #{checkMessageJSON}"
              return callback error

            logger.debug "comparing ivs"
            checkMessage.iv == message.iv

          callback null, found
      else
        logger.debug "searching 30 messages from room: #{room} for duplicates"
        #check last 30 for dupes
        getMessages username, room, 30, (err, data) ->
          logger.error "error getting messages" if err?
          return callback err if err
          found = _.find data, (checkMessageJSON) ->
            try
              logger.debug "parsing #{checkMessageJSON}"
              checkMessage = JSON.parse(checkMessageJSON)
            catch error
              logger.error "error parsing #{checkMessageJSON}"
              return callback error

            logger.debug "comparing ivs"
            checkMessage.iv == message.iv

          callback null, found
    else
      callback null, false
