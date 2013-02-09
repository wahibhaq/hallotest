redis = require("redis")
rc = redis.createClient 6379, "127.0.0.1"
rc.auth "x3frgFyLaDH0oPVTMvDJHLUKBz8V+040"
minclient = 1000
clients = 100
for i in [minclient..minclient+clients-1] by 1
  num = i
  keys = [
    "users:test#{num}",
    "friends:test#{num}",
    "invites:test#{num}",
    "invited:test#{num}",
    "test:test#{num}:id",
    "messages:test:test#{num}",
    "conversations:test#{num}"]
  rc.del keys, (err, blah) ->
    


