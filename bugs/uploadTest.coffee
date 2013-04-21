should = require("should")
http = require("request")
fs = require("fs")
baseUri = "http://localhost:8000"
Throttle = require 'throttle'

describe "uploadtest", () ->
  it 'upload image', (done) ->
    r = http.post baseUri + "/images", (err, res, body) ->
      if err
        done err
      else
        res.statusCode.should.equal 204
        done()

    throttle = new Throttle(1000000)
    fs.createReadStream("testImage").pipe throttle
    throttle.path = "iv"
    form = r.form()
    form.append "image", throttle