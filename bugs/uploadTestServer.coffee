http = require('http')
express = require("express")
formidable = require 'formidable'
pkgcloud = require 'pkgcloud'
stream = require 'readable-stream'

rackspaceApiKey = "5241b31d69d4ef97e2143c78836155c0"
rackspaceImageContainer = "surespotImagesLocal"

rackspace = pkgcloud.storage.createClient {provider: 'rackspace', username: 'adam2fours', apiKey: rackspaceApiKey}

app = express()
app.configure ->
  app.use app.router
  app.use (err, req, res, next) ->
    console.log 'error', "middlewareError #{err}"
    res.send err.status or 500

server = http.createServer app
server.listen(8000)

app.post "/images", (req, res, next) ->
  form = new formidable.IncomingForm()
  form.onPart = (part) ->
    return form.handlePart part unless part.filename?
    path = "somepath"
    console.log "received part: #{part.filename}, uploading to rackspace at: #{path}"
    part.pipe rackspace.upload {container: rackspaceImageContainer, remote: path}, (err) ->
      #todo send messageerror on socket
      return console.log err if err?
      console.log 'uploaded completed'
      res.send 204

    console.log 'stream piped'

  form.on 'error', (err) ->
    next new Error err

  form.on 'end', ->
    console.log 'form end'

  form.parse req


