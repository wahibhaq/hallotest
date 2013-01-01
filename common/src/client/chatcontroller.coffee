define [
  "socket.io",
  "./encryptioncontroller",
  "./networkcontroller",
  './utils',
  'jquery',
  'knockout',
  './viewmodels/UserViewModel'],
  (io,
   encryptioncontroller,
   networkcontroller,
   utils,
   $,
   ko,
   UserViewModel) ->
    class ChatController
      _socket: null
      _uicontroller: null
      _callbacks: {}


      #check for existing key
      #networkController.get

      #get the remote user's public key

      #encrypte the symmetric key and send it to the other guy
      #todo generate key on the fly?
      #store the key locally

      #todo indicate on friends list

      setConnectCallback: (callback) ->
        @_callbacks["connect"] = callback

      setMessageCallback: (callback) ->
        @_callbacks["message"] = callback
      setNotificationCallback: (callback) ->
        @_callbacks["notification"] = callback
      setFriendCallback: (callback) ->
        @_callbacks["friend"] = callback

      #remote username is the other name
      emit: (type, data) ->
        @_socket.emit type, data

      sendMessage: (to, text) ->
        if text? and text.length > 0
          encryptioncontroller.ecEncrypt to, text, (ciphertext) =>
            message = {}
            message.text = ciphertext
            console.log "plaintext: " + text
            console.log "ciphertext: " + JSON.stringify(message.text)
            message.from = UserViewModel.getUsername()
            message.to = to
            @_socket.send JSON.stringify(message)

      disconnect: ->
        if @_socket?
          @_socket?.socket.disconnect()


      connect:  ->
        #make sure socket is disconnected
        @disconnect()

        if not @_socket? or not @_socket.socket.connected
          nullsocket = not @_socket?

          if nullsocket
            #   console.log ('creating new socket connection')
            @_socket = io.connect()

          else
            #  console.log ('reconnecting existing socket connection')
            @_socket.socket.connect()

          #only add the event handlers once
          if nullsocket
            @_socket.on "connect", =>
              console.log "CON"
              #   console.log ("cc #{@cc}")
              @_callbacks["connect"]?()


            # lines.addClass('connected');
            # theclient.join(sessionStore.getItem('username'));
            @_socket.on "message", (data) =>
              console.log "message"
              @_callbacks["message"]?(data)

            @_socket.on "disconnect", ->
              console.log "DISC"

            @_socket.on "notification", (notification) =>
              console.log "notification"
              @_callbacks["notification"]?(notification)

            @_socket.on "friend", (username) =>
              console.log "friend"
              @_callbacks["friend"]?(username)
    return new ChatController()


