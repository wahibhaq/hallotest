redis = require("redis")
rc = redis.createClient()
#rc.auth "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040"
minclient = 0
clients = 1000
keys = []
for i in [minclient..minclient + clients - 1] by 1
  keys.push "users:test#{i}"
  keys.push "friends:test#{i}"
  keys.push "invites:test#{i}"
  keys.push "invited:test#{i}"
  keys.push "test#{i}:test#{i + 1}:id"
  keys.push "messages:test#{i}:test#{i + 1}"
  keys.push "conversations:test#{i}"

rc.del keys, (err, blah) ->
  console.log 'done'



