cloudfiles = require 'cloudfiles'
fs = require 'fs'
dateformat = require 'dateformat'
crypto = require 'crypto'
zlib = require 'zlib'
stream = require 'readable-stream'


sourceFile = process.argv[2]
rackspaceApiKey = process.env.SURESPOT_RACKSPACE_API_KEY
rackspaceBackupContainer = process.env.SURESPOT_RACKSPACE_BACKUP_CONTAINER
rackspaceUsername = process.env.SURESPOT_RACKSPACE_USERNAME
encryptionPassword = process.env.SURESPOT_RACKSPACE_BACKUP_ENCRYPTION_PASSWORD

if not rackspaceApiKey?
  console.error "no rackspace api key"
  process.exit(1)

if not rackspaceBackupContainer?
  console.error "no rackspace container"
  process.exit(1)

if not rackspaceUsername?
  console.error "no rackspace username"
  process.exit(1)

if not encryptionPassword?
  console.error "no file encryption password"
  process.exit(1)

if not sourceFile?
  console.error "no file"
  process.exit(1)

cfClient = cloudfiles.createClient {auth: { username: rackspaceUsername, apiKey: rackspaceApiKey}}
ensureCfClientAuthorized = (force, callback) ->
  if not cfClient.authorized or force
    cfClient.authorized = false
    cfClient.setAuth (err) ->
      return callback err if err?
      callback()
  else
    callback()



retry = 0
postFile = (force, path, file, callback) ->
  ensureCfClientAuthorized force, (err) ->
    return process.exit 1 if err?
    cfClient.addFile rackspaceBackupContainer, {remote: path, local: file}, (err, uploaded) ->
      if err?
        #try to auth once
        if (err.message.indexOf ("Unauthorized") > -1) && (retry is 0)
          retry++
          postFile true, path, file, callback
        else
          callback err

      else
        callback null, uploaded



path = dateformat("yyyymmdd_HHMMss_") + "#{sourceFile}"

console.log "backing up #{sourceFile} to #{path}"
postFile false, path, sourceFile, (err, uploaded) ->
  if err?
    console.error "error: #{err}"
    process.exit 1
  console.log "uploaded: #{uploaded}"
  process.exit uploaded ? 0 : 1



