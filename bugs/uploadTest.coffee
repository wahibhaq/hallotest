should = require("should")
http = require("request")
fs = require("fs")
baseUri = "http://localhost:8000"

describe "uploadtest", () ->
  it 'upload image', (done) ->
    r = http.post baseUri + "/images", (err, res, body) ->
      if err
        done err
      else
        res.statusCode.should.equal 204
        done()

    form = r.form()
    form.append "image", fs.createReadStream "testImage"