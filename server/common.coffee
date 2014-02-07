exports.getSpotName = (from, to) ->
    if from < to then from + ":" + to else to + ":" + from


exports.getOtherSpotUser = (spot, user) ->
  users = spot.split ":"
  if user == users[0] then return users[1] else return users[0]
