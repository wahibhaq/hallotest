define [
  "./encryptioncontroller",
  "./networkcontroller",
  "./chatcontroller",
  './uicontroller',
  "./utils",
  "./viewmodels/FriendsViewModel",
  "./viewmodels/UserViewModel",
  "jquery"],
  (encryptioncontroller,
   networkcontroller,
   chatcontroller,
   uicontroller,
   utils,
   FriendsViewModel,
   UserViewModel,
   $) ->
    class UserController
      encryptionReady: false
      signupCredsReady: false
      username: null
      password: null

      #todo handle multiple users on same device
      login: (username, password, callback) ->
        networkcontroller.login username, password, (loginSuccessCallback = ->
          chatcontroller.connect()
          UserViewModel.setUsername username
          $(".dynamicConversationPage").remove()
          FriendsViewModel.load()
          $.mobile.changePage "#friends"

        ), unauthorizedCallback = ->
          alert "Unauthorized"



      #todo handle multiple users on same device
      signup: (username, password) ->
        @signupCredsReady = true
        @username = username
        @password = password

        #see if the key is there
        unless @encryptionReady
          if encryptioncontroller.publickey
            @encryptionReady = true
          else

            #todo alert user waiting on key
            return alert("generating key pair, you will be logged in when this has completed.")

        #signup and upload public key
        @signupanduploadkey()  if @encryptionReady and @signupCredsReady

      signupanduploadkey: ->
        u = @username
        networkcontroller.addUser @username, @password, encryptioncontroller.publickey, (signupSuccessCallback = ->
          chatcontroller.connect()
          UserViewModel.setUsername u
          $(".dynamicConversationPage").remove()
          FriendsViewModel.load()
          $.mobile.changePage "#friends"#, transition: "slide"

        ), signupErrorCallback = ->
          alert "error creating user"

    encryptioncontroller.readycallback = (ready) ->
      encryptionReady = ready

      #signup and upload public key
      signupanduploadkey()  if @encryptionReady and @signupCredsReady


    userController = new UserController()

    $("#loginform").bind "submit", (e) ->
      e.preventDefault()
      username = $("#usernameinput").val()
      password = $("#passwordInput").val()
      userController.login username, password

    $("#signupform").bind "submit", (e) ->
      e.preventDefault()
      username = $("#signupusernameinput").val()
      password = $("#signupPasswordInput").val()
      userController.signup username, password

    userController
