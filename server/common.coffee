exports.getRoomName = (from, to) ->
    if from < to then from + ":" + to else to + ":" + from
