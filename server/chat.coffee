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
  pool = new helenus.ConnectionPool({host:'127.0.0.1', port:9160, keyspace:'surespot'});
  pool.connect (err, keyspace) ->
    if (err)
      callback err

exports.insertTextMessage = (message, callback) ->
  spot = common.getSpotName(message.from, message.to)

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


exports.getMessagesBeforeId = (username, room, id, callback) ->
  cql = "select * from chatmessages where username=? and spotname=? and id < ? order by spotname desc limit 60;"
  pool.cql cql, [username, room, id], (err, results) =>
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


exports.deleteMessage = (deletingUser, fromUser, spot, id) ->
  users = spot.split ":"

  #if the deleting user is the user that sent the message delete it in both places
  if deletingUser is fromUser

    cql = "begin batch
           delete from chatmessages where username=? and spotname=? and id = ?
           delete from chatmessages where username=? and spotname=? and id = ?
           apply batch"

    pool.cql cql, [users[0], spot, id, users[1], spot, id], (err, results) =>
      logger.error err if err?

  else
    #deleting user was the recipient, just delete it from their messages
    cql = "delete from chatmessages where username=? and spotname=? and id = ?;"
    pool.cql cql, [deletingUser, spot, id], (err, results) =>
      logger.error err if err?

exports.getMessage = (username, room, id, callback) ->
  cql = "select * from chatmessages where username=? and spotname=? and id = ?;"
  pool.cql cql, [username, room, id], (err, results) =>
    return callback err if err?
    return callback null, @remapMessages results


exports.updateMessageShareable = (room, id, bShareable, callback) ->
  users = room.split ":"
  cql = "begin batch
         update chatmessages set shareable = ? where username=? and spotname=? and id = ?
         update chatmessages set shareable = ? where username=? and spotname=? and id = ?
         apply batch"

  pool.cql cql, [bShareable, users[0], room, id, bShareable, users[1], room, id], (err, results) =>
    return callback err if err?
    callback()



exports.getControlMessages = (room, count, fn) ->
    rc.zrange "cm:" + room, -count, -1, fn

exports.getUserControlMessages = (user, count, fn) ->
    rc.zrange "cu:" + user, -count, -1, fn




