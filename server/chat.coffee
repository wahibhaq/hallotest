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


exports.remapMessages = (results, reverse) ->
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
          if value?
            message['dataSize'] = value
        else
          if value? then message[name] = value else return

    #insert at begining to reverse order
    if reverse
      messages.unshift message
    else
      messages.push message

  return messages


exports.getAllMessages = (username, spot, callback) ->
  #get all messages for a user in a spot
  cql = "select * from chatmessages where username=? and spotname=?;"
  pool.cql cql, [username, spot], (err, results) =>
    return callback err if err?
    return callback null, @remapMessages results, true

exports.getMessages = (username, room, count, callback) ->
  cql = "select * from chatmessages where username=? and spotname=? limit #{count};"
  pool.cql cql, [username, room], (err, results) =>
    return callback err if err?
    return callback null, @remapMessages results, false


exports.getMessagesBeforeId = (username, spot, id, callback) ->
  logger.debug "getMessagesBeforeId, username: #{username}, spot: #{spot}, id: #{id}"
  cql = "select * from chatmessages where username=? and spotname=? and id<? limit 60;"
  pool.cql cql, [username, spot, id], (err, results) =>
    return callback err if err?
    return callback null, @remapMessages results, false


exports.getMessagesAfterId = (username, spot, id, callback) ->
  logger.debug "getMessagesAfterId, username: #{username}, spot: #{spot}, id: #{id}"
  if id is -1
    callback null, null
  else
    if id is 0
      this.getMessages username, spot, 30, callback
    else
      cql = "select * from chatmessages where username=? and spotname=? and id > ?;"
      pool.cql cql, [username, spot, id], (err, results) =>
        return callback err if err?
        messages = @remapMessages results, false
        return callback null, messages


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


exports.deleteAllMessages = (username, spot, messageIds, callback) ->
  #logger.debug "deleteAllMessages messageIds: #{JSON.stringify(messageIds)}"
  otherUser = common.getOtherSpotUser spot, username

  params = [username, spot]

  #delete all messages for username in spot


  cql = "begin batch
         delete from chatmessages where username=? and spotname=? "

  #delete all username's messages for the other user where ids match
  # add delete statements for my messages in their chat table because we can't use in with ids, or equal with fromuser which can't be in the primary key because it fucks up the other queries
  #https://issues.apache.org/jira/browse/CASSANDRA-6173
  #cheesy as fuck but it'll do for now until we can delete by secondary columns or use < >, or even IN with primary key columns

  for id in messageIds
    cql += "delete from chatmessages where username=? and spotname=? and id = ? "
    params = params.concat([otherUser, spot, id])

  cql += "apply batch"

  #logger.debug "sending cql: #{cql}"
  #logger.debug "params: #{JSON.stringify(params)}"
  pool.cql cql, params, callback

exports.getMessage = (username, room, id, callback) ->
  cql = "select * from chatmessages where username=? and spotname=? and id = ?;"
  pool.cql cql, [username, room, id], (err, results) =>
    return callback err if err?
    return callback null, @remapMessages results, false


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




