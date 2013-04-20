http = require('http')
express = require("express")
formidable = require 'formidable'
pkgcloud = require 'pkgcloud'
stream = require 'readable-stream'

rackspaceApiKey = "6c20021990a1fd28f0afa8f0c793599a"
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
    outStream = new stream.PassThrough()

    part.on 'data', (buffer) ->
      form.pause()
      console.log 'received part data'
      outStream.write buffer, ->
        form.resume()

    part.on 'end', ->
      form.pause()
      console.log 'received part end'
      outStream.end ->
        form.resume()

    path = "somepath"
    console.log "received part: #{part.filename}, uploading to rackspace at: #{path}"
    outStream.pipe rackspace.upload {container: rackspaceImageContainer, remote: path}, (err) ->
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


