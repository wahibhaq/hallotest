define [
  "jquery",
  "knockout",
  './ListViewModel',
  './UserViewModel',
  'networkcontroller',
  'chatcontroller',
  'encryptioncontroller',
  'uicontroller',
  '../utils'],
    ($,
     ko,
     ListViewModel,
     UserViewModel,
     networkcontroller,
     chatcontroller,
     encryptioncontroller,
     uicontroller,
     utils) ->
      class ConversationViewModel extends ListViewModel
        remoteusername = null
        constructor: (remoteusername) ->
          super()

          @remoteusername = remoteusername

          $.each($("#conversation_#{remoteusername} h1"), (index, value) =>
            ko.applyBindings @, value)


        load: (callback) =>
          networkcontroller.getMessages @remoteusername, (data) =>
            @itemList?.removeAll()
            $.each data, (index, messageString) =>
              message = JSON.parse(messageString)
              @addMessage message
              #@addItem message
            callback()


         #$("#friendslist").on "click", "a.friendclick", ->
        #username = sessionStorage.getItem("username")
        #remoteusername = $(this).text()
        title: ->
          "surespot / #{@remoteusername}"




        addMessage: (message) ->
          console.log ("received encrypted text: " + message.text)
          encryptioncontroller.ecDecrypt(@remoteusername, message.text, (plaintext) =>
            @addItem message.from + ': ' + plaintext)

        logout: ->
          uicontroller.logout()
