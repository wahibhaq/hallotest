redis = require("redis")
rc = redis.createClient()
#rc.auth "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040"
minclient = 0
clients = 10000

clean1up = (max ,i, done) ->
  keys = []
  keys.push "friends:test#{i}"
  keys.push "invites:test#{i}"
  keys.push "invited:test#{i}"
  keys.push "test#{i}:test#{i + 1}:id"
  keys.push "messages:test#{i}:test#{i + 1}"
  keys.push "conversations:test#{i}"
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

