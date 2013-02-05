define ['redis'], (redis) ->
  class DAL
    _rc = null
    constructor: (port, hostname, auth) ->
      if port? and hostname? and auth?
        @_rc = redis.createClient(port, hostname)
        @_rc.auth auth
      else
        @_rc = redis.createClient()

    getFriends: (username, callback) ->
      @_rc.smembers "friends:#{username}", callback

    #is friendname a friend of username
    isFriend: (username, friendname, callback) ->
      @_rc.sismember "friends:#{username}", friendname, callback


    inviteExists: (username, friendname, callback) ->
      @_rc.sismember "invited:#{username}", friendname, (err, result) =>
        return callback err if err?
        return callback null, false if not result
        @_rc.sismember "invites:#{friendname}", username, callback