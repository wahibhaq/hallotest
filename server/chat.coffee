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
    return callback null, @remapMessages results, false

exports.getMessages = (username, spot, count, callback) ->
  cql = "select * from chatmessages where username=? and spotname=? order by spotname desc limit #{count};"
  pool.cql cql, [username, spot], (err, results) =>
    return callback err if err?
    return callback null, @remapMessages results, true


exports.getMessagesBeforeId = (username, spot, id, callback) ->
  logger.debug "getMessagesBeforeId, username: #{username}, spot: #{spot}, id: #{id}"
  cql = "select * from chatmessages where username=? and spotname=? and id<? order by spotname desc limit 60;"
  pool.cql cql, [username, spot, id], (err, results) =>
    return callback err if err?
    return callback null, @remapMessages results, true


exports.getMessagesAfterId = (username, spot, id, callback) ->
  logger.debug "getMessagesAfterId, username: #{username}, spot: #{spot}, id: #{id}"
  if id is -1
    callback null, null
  else
    if id is 0
      this.getMessages username, spot, 30, callback
    else
      cql = "select * from chatmessages where username=? and spotname=? and id > ? order by spotname desc;"
      pool.cql cql, [username, spot, id], (err, results) =>
        return callback err if err?
        messages = @remapMessages results, true
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


exports.deleteMessages = (username, spot, messageIds, callback) ->
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


exports.deleteAllMessages = (spot, callback) ->
  users = spot.split ":"

  cql = "begin batch
         delete from chatmessages where username=? and spotname=?
         delete from chatmessages where username=? and spotname=?
         apply batch"

  pool.cql cql, [users[0], spot, users[1], spot], callback


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


#message control message stuff

exports.remapControlMessages = (results, reverse) ->
  messages = []
  #map to array of json messages
  results.forEach (row) ->
    message = {}
    row.forEach (name, value, ts, ttl) ->
      switch name
        when 'username','spotname'
          return
        when 'fromuser'
          message['from'] = value
        else
          if value? then message[name] = value else return

    #insert at begining to reverse order
    if reverse
      messages.unshift message
    else
      messages.push message

  return messages


exports.remapControlMessageIds = (results) ->
  ids = []
  #map to array of ids
  results.forEach (row) ->
    row.forEach (name, value, ts, ttl) ->
      switch name
        when 'id'
          if value? then ids.push value else return
  return ids

exports.getAllControlMessageIds = (username, spot,  callback) ->
  cql = "select id from messagecontrolmessages where username=? and spotname=?;"
  pool.cql cql, [username, spot], (err, results) =>
    return callback err if err?
    return callback null, @remapControlMessageIds results, false


exports.getControlMessages = (username, room, count, callback) ->
  cql = "select * from messagecontrolmessages where username=? and spotname=? order by spotname desc limit #{count};"
  pool.cql cql, [username, room], (err, results) =>
    return callback err if err?
    return callback null, @remapControlMessages results, true


exports.getControlMessagesAfterId = (username, spot, id, callback) ->
  logger.debug "getControlMessagesAfterId, username: #{username}, spot: #{spot}, id: #{id}"
  if id is -1
    callback null, null
  else
    if id is 0
      this.getControlMessages username, spot, 60, callback
    else
      cql = "select * from messagecontrolmessages where username=? and spotname=? and id > ? order by spotname desc;"
      pool.cql cql, [username, spot, id], (err, results) =>
        return callback err if err?
        messages = @remapControlMessages results, true
        return callback null, messages

exports.insertMessageControlMessage = (spot, message, callback) ->
  #denormalize using username as partition key so all retrieval for a user
  #occurs on the same node as we are going to be pulling multiple
  users = spot.split ":"
  cql =
    "BEGIN BATCH
          INSERT INTO messagecontrolmessages (username, spotname, id, type, action, data, moredata, fromuser)
          VALUES (?,?,?,?,?,?,?,?)
          INSERT INTO messagecontrolmessages (username, spotname, id, type, action, data, moredata, fromuser)
          VALUES (?,?,?,?,?,?,?,?)
          APPLY BATCH"

  #logger.debug "sending cql #{cql}"

  pool.cql cql, [
    users[0],
    spot,
    message.id,
    message.type,
    message.action,
    message.data,
    message.moredata,
    message.from,
    users[1],
    spot,
    message.id,
    message.type,
    message.action,
    message.data,
    message.moredata,
    message.from
  ], callback



exports.deleteControlMessages = (spot, messageIds, callback) ->
  #logger.debug "deleteAllMessages messageIds: #{JSON.stringify(messageIds)}"
  users = spot.split ":"

  #delete control messages for username in spot by id
  cql = "begin batch "
  params = [];

  #delete all username'scontrol messages for the user where ids match
  # add delete statements for my messages in their chat table because we can't use in with ids, or equal with fromuser which can't be in the primary key because it fucks up the other queries
  #https://issues.apache.org/jira/browse/CASSANDRA-6173
  #cheesy as fuck but it'll do for now until we can delete by secondary columns or use < >, or even IN with primary key columns
  for id in messageIds
    cql += "delete from messagecontrolmessages where username=? and spotname=? and id = ? "
    params = params.concat([users[0], spot, id])
    cql += "delete from messagecontrolmessages where username=? and spotname=? and id = ? "
    params = params.concat([users[1], spot, id])

  cql += "apply batch"

  #logger.debug "sending cql: #{cql}"
  #logger.debug "params: #{JSON.stringify(params)}"
  pool.cql cql, params, callback

exports.deleteAllControlMessages = (spot, callback) ->
  users = spot.split ":"
  cql = "begin batch
         delete from messagecontrolmessages where username=? and spotname=?
         delete from messagecontrolmessages where username=? and spotname=?
         apply batch"

  pool.cql cql, [users[0], spot, users[1], spot], callback

#user control message stuff

exports.insertUserControlMessage = (user, message, callback) ->
  #denormalize using username as partition key so all retrieval for a user
  #occurs on the same node as we are going to be pulling multiple
  cql =
    "INSERT INTO usercontrolmessages (username, id, type, action, data, moredata)
     VALUES (?,?,?,?,?,?);"

  #logger.debug "sending cql #{cql}"

  pool.cql cql, [
    user,
    message.id,
    message.type,
    message.action,
    message.data,
    message.moredata,
  ], callback

exports.remapUserControlMessages = (results, reverse) ->
  messages = []
  #map to array of json messages
  results.forEach (row) ->
    message = {}
    row.forEach (name, value, ts, ttl) ->
      switch name
        when 'username'
          return
        else
          if value? then message[name] = value else return

    #insert at begining to reverse order
    if reverse
      messages.unshift message
    else
      messages.push message

  return messages

exports.getUserControlMessages = (user, count, callback) ->
  cql = "select * from usercontrolmessages where username=? order by id desc limit #{count};"
  pool.cql cql, [user], (err, results) =>
    return callback err if err?
    return callback null, @remapUserControlMessages results, true

exports.getUserControlMessagesAfterId = (user, id, callback) ->
    if id is -1
      callback null, null
    else
      if id is 0
        this.getUserControlMessages user, 20, callback
      else
        cql = "select * from usercontrolmessages where username=? and id > ? order by id desc;"
        pool.cql cql, [user, id], (err, results) =>
          return callback err if err?
          messages = @remapUserControlMessages results, true
          return callback null, messages


exports.getAllUserControlMessageIds = (username, callback) ->
  cql = "select id from usercontrolmessages where username=?;"
  pool.cql cql, [username], (err, results) =>
    return callback err if err?
    return callback null, @remapControlMessageIds results

exports.deleteUserControlMessages = (user, messageIds, callback) ->
  #logger.debug "deleteAllMessages messageIds: #{JSON.stringify(messageIds)}"

  #delete user control messages for username by id
  cql = "begin batch "
  params = [];

  #delete all username'scontrol messages for the user where ids match
  # add delete statements for my messages in their chat table because we can't use in with ids, or equal with fromuser which can't be in the primary key because it fucks up the other queries
  #https://issues.apache.org/jira/browse/CASSANDRA-6173
  #cheesy as fuck but it'll do for now until we can delete by secondary columns or use < >, or even IN with primary key columns
  for id in messageIds
    cql += "delete from usercontrolmessages where username=? and id = ? "
    params = params.concat([user, id])

  cql += "apply batch"

  #logger.debug "sending cql: #{cql}"
  #logger.debug "params: #{JSON.stringify(params)}"
  pool.cql cql, params, callback

exports.deleteAllUserControlMessages = (user, callback) ->
  cql = "delete from usercontrolmessages where username=?;"
  pool.cql cql, [user], callback


#migration crap

exports.migrateDeleteMessages = (username, spot, messageIds, callback) ->
  params = []
  logger.debug "deleting #{username} #{spot} #{messageIds}"

  #delete all username's messages for the other user where ids match
  # add delete statements for my messages in their chat table because we can't use in with ids, or equal with fromuser which can't be in the primary key because it fucks up the other queries
  #https://issues.apache.org/jira/browse/CASSANDRA-6173
  #cheesy as fuck but it'll do for now until we can delete by secondary columns or use < >, or even IN with primary key columns
  cql = "begin batch "

  for id in messageIds
    cql += "delete from chatmessages where username=? and spotname=? and id = ? "
    params = params.concat([username, spot, parseInt(id)])

  cql += "apply batch"

  #logger.debug "sending cql: #{cql}"
  #logger.debug "params: #{JSON.stringify(params)}"
  pool.cql cql, params, (err, results) ->
    logger.debug "err: #{err}" if err?
    logger.debug "results: #{results}"
    callback err, results


