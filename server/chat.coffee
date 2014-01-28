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


exports.remapMessages = (results) ->
  messages = []
  #map to array of json messages
  results.forEach (row) ->
    message = {}
    row.forEach (name, value, ts, ttl) ->
      switch name
        when 'username','spotname'
          return
        when 'touser'
          message['to'] = value
        when 'fromuser'
          message['from'] = value
        when 'datetime'
          message[name] = value.getTime()
        when 'mimetype'
          message['mimeType'] = value
        when 'toversion'
          message['toVersion'] = value
        when 'fromversion'
          message['fromVersion'] = value
        when 'datasize'
          message['dataSize'] = value
        else
          if value? then message[name] = value else return

    #insert at begining to reverse order
    messages.unshift message

  return messages

exports.getMessages = (username, room, count, callback) ->
  cql = "select * from chatmessages where username=? and spotname=? order by spotname desc limit #{count};"
  pool.cql cql, [username, room], (err, results) =>
    return callback err if err?
    return callback null, @remapMessages results




exports.getMessagesAfterId = (username, room, id, callback) ->
  if id is -1
    callback null, null
  else
    if id is 0
      this.getMessages username, room, 30, callback
    else
      cql = "select * from chatmessages where username=? and spotname=? and id > ? order by spotname desc;"
      pool.cql cql, [username, room, id], (err, results) =>
        return callback err if err?
        return callback null, @remapMessages results


exports.getControlMessages = (room, count, fn) ->
    rc.zrange "cm:" + room, -count, -1, fn

exports.getUserControlMessages = (user, count, fn) ->
    rc.zrange "cu:" + user, -count, -1, fn


exports.getMessagesBeforeId = (username, room, id, fn) ->
    rc.zrangebyscore "m:#{room}", id - 60, "(" + id, 'withscores', (err, data) ->
      filterDeletedMessages username, room, data, fn


