redis = require("redis")
rc = redis.createClient()
rc.select 1
#rc.auth "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040"
minclient = 0
clients = 10000

clean1up = (max ,i, done) ->
  keys = []
  keys.push "f:test#{i}"
  keys.push "is:test#{i}"
  keys.push "ir:test#{i}"
  keys.push "m:test#{i}:test#{i + 1}:id"
  keys.push "m:test#{i}:test#{i + 1}"
  keys.push "c:test#{i}"
  #rc.del keys1, (err, blah) ->
  # return done err if err?
  rc.del keys, (err, blah) ->
    return done err if err?
    if i+1 < max
      clean1up max, i+1, done
    else
      done()


clean1up clients, 0, ->
  process.exit(0)

