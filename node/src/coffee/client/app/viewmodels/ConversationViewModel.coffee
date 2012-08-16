define [
  "jquery",
  "knockout",
  './ListViewModel',
  './UserViewModel',
  'networkcontroller',
  'chatcontroller',
  'encryptioncontroller'],
    ($,
     ko,
     ListViewModel,
     UserViewModel,
     networkcontroller,
     chatcontroller,
     encryptioncontroller) ->
      class ConversationViewModel extends ListViewModel
        spot = null
        remoteusername = null
        constructor: (remoteusername, spot) ->
          super()
          @spot = spot
          @remoteusername = remoteusername

          $.each($("#conversation_#{spot} h1"), (index, value) =>
            ko.applyBindings @, value)


        load: (callback) =>
          networkcontroller.getMessages @spot, (data) =>
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
          "surespot / #{UserViewModel.username()} / #{@remoteusername}"




        addMessage: (message) ->
          @addItem message.user + ': ' + encryptioncontroller.symDecrypt(message.room, message.text)

