http = require('http')
express = require("express")
formidable = require 'formidable'
pkgcloud = require 'pkgcloud'
stream = require 'readable-stream'
cloudfiles = require 'cloudfiles'
Throttle = require 'throttle'

rackspaceApiKey = "6c20021990a1fd28f0afa8f0c793599a"
rackspaceImageContainer = "surespotImagesLocal"

rackspace = pkgcloud.storage.createClient {provider: 'rackspace', username: 'adam2fours', apiKey: rackspaceApiKey}
cfClient = cloudfiles.createClient {auth: { username: 'adam2fours', apiKey: rackspaceApiKey}}

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

    #outStream = new stream.PassThrough()-
    #throttle = new Throttle(200)


#    part.pipe(throttle)

#    part.on 'data', (buffer) ->
#      #form.pause()
#      console.log 'received part data'
#      process.nextTick () ->
#        outStream.write buffer, ->
#        #form.resume()
#
#    part.on 'end', ->
#      #form.pause()
#      console.log 'received part end'
#
#      outStream.end ->
#        #form.resume()

    path = "somepath"
    console.log "received part: #{part.filename}, uploading to rackspace at: #{path}"

    ensureAuthorized = (callback) ->
      if not cfClient.authorized
        cfClient.setAuth ->
          callback()
      else
        callback()


    retry = 0
    goodToken = undefined
    postFile = (callback) ->
      ensureAuthorized ->

        if retry is 0
          goodToken = cfClient.config.authToken
          cfClient.config.authToken = "yourmama"
        else
          cfClient.config.authToken = goodToken

        cfClient.addFile rackspaceImageContainer, {remote: path, stream: part}, (err, uploaded) ->
  #    rackspace.upload({container: rackspaceImageContainer, remote: path, stream: outStream }, (err) ->
        #todo send messageerror on socket
          if err?
            #try to auth once
            if (err.message.indexOf ("Unauthorized") > -1) && (retry is 0)
              retry++
              postFile callback
            else
              callback err

          else
            callback()



    postFile (err) ->
      if err?
        console.log err
        form._error err
      else
        console.log 'uploaded completed'
        res.send 204



    console.log 'stream piped'
    #req.resume()

  form.on 'error', (err) ->
    next new Error err

  form.on 'end', ->
    console.log 'form end'

  form.parse req


