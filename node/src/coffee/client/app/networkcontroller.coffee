define ["jquery"], ($) ->

  buildUrl: (path) ->
    $(document.body).data('base') + path

  addUser: (username, password, publickey, successCallback, errorCallback) ->
    
    #todo use json objects
    user = {}
    user.username = username
    user.password = password
    user.publickey = publickey
    $.post(@buildUrl("/users"), JSON.stringify(user)).success(successCallback).error errorCallback

  login: (username, password, successCallback, errorCallback) ->
    console.log "login"
    $.post(@buildUrl("/login"), "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}").success(successCallback).error errorCallback

  logout: (successCallback, errorCallback) ->
    $.ajax
      type: "POST"
      url: @buildUrl("/logout")
      dataType:"json"
      contentType:"application/json"
      success: successCallback
      error: errorCallback


  getConversationKey: (room, successCallback, errorCallback) ->
    $.get(@buildUrl("/conversations/" + room + "/key/")).success(successCallback).error errorCallback

  
  #  setConversationKey:function (username,key,successCallback, errorCallback) {
  #   $.post('/conversations/' + room + "/keys/" + username,  {key:key}).success(successCallback).error(errorCallback);
  # },
  getPublicKey: (username, successCallback, errorCallback) ->
    console.log "getpublickey"
    $.get(@buildUrl("/publickey/#{username}")).success(successCallback).error errorCallback

  #setPublicKey: (username, publickey, successCallback, errorCallback) ->
   # console.log "setpublickey"
   # $.post("/users/" + username + "/publickey").success(successCallback).error errorCallback

  getFriends: (username, successCallback, errorCallback) ->
    console.log "getFriends"
    $.get(@buildUrl("/friends")).success(successCallback).error errorCallback

  getMessages: (room, successCallback, errorCallback) ->
    console.log "getMessages"
    $.get(@buildUrl("/conversations/" + room + "/messages")).success(successCallback).error errorCallback

  invite: (friendname, successCallback, errorCallback) ->
    console.log "invite"
    $.post((@buildUrl "/invite/#{friendname}")).success(successCallback).error errorCallback

  respondToInvite: (friendname, choice, successCallback, errorCallback) ->
    $.post((@buildUrl "/invites/#{friendname}/#{choice}")).success(successCallback).error errorCallback

  getNotifications: (successCallback, errorCallback) ->
    $.get((@buildUrl "/notifications")).success(successCallback).error errorCallback
#$.ajax({
#         type:'POST',
#         url:,
#         data:
#         dataType:"json",
#         contentType:"application/json",
#         success:successCallback,
#         error:errorCallback
#         })
