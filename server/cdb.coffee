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

poolIps = process.env.SURESPOT_CASSANDRA_IPS ? '127.0.0.1'
poolIps = poolIps.split ":"

exports.connect = (callback) ->
  pool = new helenus.ConnectionPool(
    hosts: poolIps
    keyspace: 'surespot'
  );
  pool.connect (err, keyspace) ->
    if (err)
      callback err

exports.insertMessage = (message, callback) ->
  spot = common.getSpotName(message.from, message.to)

  cql =
  "BEGIN BATCH
  INSERT INTO chatmessages (username, spotname, id, datetime, fromuser, fromversion, touser, toversion, iv, data, mimeType, datasize)
  VALUES (?, ?, ?, ?, ?,?,?,?,?,?,?,? )
  INSERT INTO chatmessages (username, spotname, id, datetime, fromuser, fromversion, touser, toversion, iv, data, mimeType, datasize)
  VALUES (?, ?, ?, ?, ?,?,?,?,?,?,?,? )
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
    message.dataSize,

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
    message.mimeType,
    message.dataSize,
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
    #todo change client to handle json object
    if reverse
      messages.unshift JSON.stringify(message)
    else
      messages.push JSON.stringify(message)

  return messages


exports.getAllMessages = (username, spot, callback) ->
  #get all messages for a user in a spot
  cql = "select * from chatmessages where username=? and spotname=?;"
  pool.cql cql, [username, spot], (err, results) =>
    if err
      logger.error "error getting all messages for #{username}, spot: #{spot}"
      return callback err
    return callback null, @remapMessages results, false

exports.getMessages = (username, spot, count, callback) ->
  cql = "select * from chatmessages where username=? and spotname=? order by spotname desc limit #{count};"
  pool.cql cql, [username, spot], (err, results) =>
    if err
      logger.error "error getting messages for #{username}, spot: #{spot}, count: #{count}"
      return callback err
    return callback null, @remapMessages results, true


exports.getMessagesBeforeId = (username, spot, id, callback) ->
  logger.debug "getMessagesBeforeId, username: #{username}, spot: #{spot}, id: #{id}"
  cql = "select * from chatmessages where username=? and spotname=? and id<? order by spotname desc limit 60;"
  pool.cql cql, [username, spot, id], (err, results) =>
    if err
      logger.error "error getting messages before id for #{username}, spot: #{spot}, id: #{id}"
      return callback err
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
        if err
          logger.error "error getting messages after id for #{username}, spot: #{spot}, id: #{id}"
          return callback err
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
    if err
      logger.error "error getting message for #{username}, spot: #{room}, id: #{id}"
      return callback err
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
      messages.unshift JSON.stringify(message)
    else
      messages.push JSON.stringify(message)

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
    if err
      logger.error "error getting message control messages id for #{username}, spot: #{spot}"
      return callback err
    return callback null, @remapControlMessageIds results, false


exports.getControlMessages = (username, room, count, callback) ->
  cql = "select * from messagecontrolmessages where username=? and spotname=? order by spotname desc limit #{count};"
  pool.cql cql, [username, room], (err, results) =>
    if err
      logger.error "error getting message control messages for #{username}, room: #{room}, count: #{count}"
      return callback err
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
        if err
          logger.error "error getting message control messages for #{username}, spot: #{spot}, id: #{id}"
          return callback err
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

exports.insertUserControlMessage = (username, message, callback) ->
  #denormalize using username as partition key so all retrieval for a user
  #occurs on the same node as we are going to be pulling multiple
  cql =
    "INSERT INTO usercontrolmessages (username, id, type, action, data, moredata)
     VALUES (?,?,?,?,?,?);"

  #logger.debug "sending cql #{cql}"
  #store moredata object as json string in case of friend image data
  if message.action is 'friendImage'
    message.moredata = JSON.stringify(message.moredata)

  pool.cql cql, [
    username,
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


    #parse json if it's friendImage
    if message.action is 'friendImage'
      message.moredata = JSON.parse(message.moredata)

    #insert at begining to reverse order
    if reverse
      messages.unshift JSON.stringify(message)
    else
      messages.push JSON.stringify(message)

  return messages

exports.getUserControlMessages = (username, count, callback) ->
  cql = "select * from usercontrolmessages where username=? order by id desc limit #{count};"
  pool.cql cql, [username], (err, results) =>
    if err
      logger.error "error getting user control messages for #{username}, count: #{count}"
      return callback err
    return callback null, @remapUserControlMessages results, true

exports.getUserControlMessagesAfterId = (username, id, callback) ->
    if id is -1
      callback null, null
    else
      if id is 0
        this.getUserControlMessages username, 20, callback
      else
        cql = "select * from usercontrolmessages where username=? and id > ? order by id desc;"
        pool.cql cql, [username, id], (err, results) =>
          if err
            logger.error "error getting user control messages for #{username}, id: #{id}"
            return callback err
          messages = @remapUserControlMessages results, true
          return callback null, messages


exports.getAllUserControlMessageIds = (username, callback) ->
  cql = "select id from usercontrolmessages where username=?;"
  pool.cql cql, [username], (err, results) =>
    return callback err if err?
    return callback null, @remapControlMessageIds results

exports.deleteUserControlMessages = (username, messageIds, callback) ->
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
    params = params.concat([username, id])

  cql += "apply batch"

  #logger.debug "sending cql: #{cql}"
  #logger.debug "params: #{JSON.stringify(params)}"
  pool.cql cql, params, callback

exports.deleteAllUserControlMessages = (username, callback) ->
  cql = "delete from usercontrolmessages where username=?;"
  pool.cql cql, [username], callback


#public keys
exports.insertPublicKeys = (username, keys, callback) ->
  cql =
    "INSERT INTO publickeys (username, version, dhPub, dhPubSig, dsaPub, dsaPubSig)
         VALUES (?,?,?,?,?,?);"

  #logger.debug "sending cql #{cql}"

  pool.cql cql, [
    username,
    keys.version,
    keys.dhPub,
    keys.dhPubSig,
    keys.dsaPub,
    keys.dsaPubSig
  ], (err, results) ->
    if err?
      logger.error "error inserting public keys for #{username}, version: #{keys.version}"
    callback(err,results)




exports.remapPublicKeys = (results) ->
  keys = {}
  #map to array of json messages
  results.forEach (row) ->

    row.forEach (name, value, ts, ttl) ->
      switch name
        when 'dhpub'
          keys['dhPub'] = value
        when 'dhpubsig'
          keys['dhPubSig'] = value
        when 'dsapub'
          keys['dsaPub'] = value
        when 'dsapubsig'
          keys['dsaPubSig'] = value
        when 'version'
          keys['version'] = "#{value}"
        when 'username'
          return
        else
          if value? then keys[name] = value else return

  return keys


exports.getPublicKeys = (username, version, callback) ->
  cql = "select * from publickeys where username=? and version=?;"
  pool.cql cql, [username,version], (err, results) =>
    if err?
      logger.error "error getting public keys for #{username}, version: #{version}"
      return callback err
    return callback null, @remapPublicKeys results


exports.deletePublicKeys = (username, callback) ->
  cql = "delete from publickeys where username=?;"
  pool.cql cql, [username], callback


#migration crap
exports.migrateInsertMessage = (message, callback) ->
  spot = common.getSpotName(message.from, message.to)

  cql =
    "BEGIN BATCH
      INSERT INTO chatmessages (username, spotname, id, datetime, fromuser, fromversion, touser, toversion, iv, data, mimeType, datasize, shareable)
      VALUES (?, ?, ?, ?, ?,?,?,?,?,?,?,?,? )
      INSERT INTO chatmessages (username, spotname, id, datetime, fromuser, fromversion, touser, toversion, iv, data, mimeType, datasize, shareable)
      VALUES (?, ?, ?, ?, ?,?,?,?,?,?,?,?,? )
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
    message.dataSize,
    message.shareable,

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
    message.mimeType,
    message.dataSize,
    message.shareable,
  ], callback



exports.migrateDeleteMessages = (username, spot, messageIds, callback) ->
  params = []
  logger.debug "deleting #{username} #{spot}"

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

exports.migrateInsertPublicKeys = (username, keys, callback) ->
  cql =
    "INSERT INTO publickeys (username, version, dhPub, dhPubSig, dsaPub, dsaPubSig)
             VALUES (?,?,?,?,?,?);"

  #logger.debug "sending cql #{cql}"

  pool.cql cql, [
    username,
    parseInt(keys.version),
    keys.dhPub,
    keys.dhPubSig,
    keys.dsaPub,
    keys.dsaPubSig
  ], callback