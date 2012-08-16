define [
  'jquery',
  './networkcontroller',
  './encryptioncontroller',
  './chatcontroller',
  './utils',
  'knockout',
  './viewmodels/ConversationViewModel',
  './viewmodels/UserViewModel'],
  ($, networkcontroller, encryptioncontroller, chatcontroller, utils, ko, ConversationViewModel, UserViewModel) ->
    class UIController

      newMessageCount:
        {}
      totalMessageCount: ko.observable(0)
      getNewMessageCount: (room) ->
        messageCount = @newMessageCount[room]
        if !messageCount?
          messageCount = ko.observable(0)
          @newMessageCount[room] = messageCount
        messageCount


      constructor: ->
        chatcontroller.setMessageCallback @appendMessage

      #   getNewMessageCount: (room) ->
      #    console.log "getting new message count for #{room}"

      _showConversationPage: (room) ->
        conversationname = room
        conversationId = "conversation_" + conversationname
        conversationPage = $("#" + conversationId)
        conversationUrl = "#" + conversationId
        if conversationPage.length is 0
          return conversationname
        else
          elementHeight = conversationPage.height()
          console.log "conversation div height before change page: " + elementHeight
          @_scrollConversation conversationname

          #switch to conversation page
          $.mobile.changePage conversationUrl
            #, transition: "slide"

          #clear message count
          setTimeout @newMessageCount[room](0), 0
          return null

      logout: ->
        networkcontroller.logout(
          ->
            chatcontroller.disconnect()
            $.mobile.changePage "#login"
              #,              transition: "slide"
              #reverse: true
            #clear friends list and blow away old conversation pages
            #todo logout event? register delegate?
            #FriendsViewModel.reset()
            $(".dynamicConversationPage").remove()
            $('.ss-logout').removeClass('ui-btn-active')
          -> alert('error'))

      resetInput: (input) ->
        input.val ''
        input.focus



      _scrollConversation: (conversationName) ->
        elementHeight = $("#conversation_" + conversationName).height()
        console.log("conversation div height" + elementHeight)

        $("html, body").stop().animate
          scrollTop: elementHeight, 300

      appendMessage: (data) =>
        if data?
          message = JSON.parse(data)
          room = message.room
          incrementCount = true
          #todo dependent on the DOM here, does it matter?
          #could store the view models in an array
          linesList = $("#lines_" + room)
          if linesList.length
            #get the view model
            conversationViewModel = ko.dataFor(linesList[0])
            conversationViewModel.addMessage message
            #   linesList.find(":first-child").remove()  if linesList.children().length is 30
            #linesList.append $("<li>").append($("<span style=\"font-weight: bold;\">").text(message.user + ": ")).append(encryptioncontroller.symDecrypt(room, message.text))
            #linesList.listview "refresh"
            #todo figure out how to do this with knockout binding
            @_scrollConversation room
            #if conversation showing then we don't need to increment the message count
            # do we?
            if $(linesList[0]).is ':visible' then incrementCount = false


          if incrementCount
            messageCount = @newMessageCount[room]
            if messageCount?
              messageCount(messageCount() + 1)
            else
              @newMessageCount[room] = ko.observable(1)
            sum = 0
            #update total message count
            for room, count of @newMessageCount
              sum += count()
            @totalMessageCount sum



      #if user hits refresh build the conversation page (if they were in one as indicated by location.hash)
      #called when user clicks on friend
      createOrShowConversation: (room, remoteuser) ->
        room = @_showConversationPage(room)
        if room?
          #todo use local storage
          #see if the conversation key exists already
          networkcontroller.getConversationKey(
            room
            , (data) =>
              if data?
                #we already have a chat, so just create the page for it
                skey = encryptioncontroller.asymDecrypt(data)

                unless skey?
                  alert 'could not decrypt conversation key'
                  return
                encryptioncontroller.symmetricKeys[room] = skey
                chatcontroller.emit "join", room
                @_createConversationPage room, remoteuser
              else
                #this is a new chat, so create a new conversation
                @_createConversation room, remoteuser
            , (err) ->
              alert 'could not get sym key')


      _createConversation: (room, remoteusername) ->
        encryptioncontroller.createSymKeys room, remoteusername, (symKeys) =>
          #todo set keys over REST and create room on success
          message = {}
          message.room = room
          message.mykey = symKeys.mykey
          message.theirname = remoteusername
          message.theirkey = symKeys.theirkey
          chatcontroller.emit "create", JSON.stringify(message)
          @_createConversationPage room, remoteusername

      recreateConversation: (conversationname) =>
        username = UserViewModel.getUsername()
        room = conversationname.substr(14)
        users = room.split("_")
        remoteusername = if username is users[0] then users[1] else users[0]
        @createOrShowConversation room, remoteusername

      _createConversationPage: (conversationname, remoteusername) ->
        users = conversationname.split("_")
        conversationId = "conversation_" + conversationname
        conversationUrl = "#" + conversationId

        #clone the conversation page template
        conversationPage = $("#conversationtemplate").clone()

        #clear the mnew message count
        @newMessageCount[conversationname](0)

        #set the id
        conversationPage.attr "id", conversationId
        conversationPage.attr "data-url", conversationUrl
        conversationPage.addClass 'conversation-page'

        #set more ids
        conversationPage.find("h1").text remoteusername
        linesList = conversationPage.find(".conversationlines").attr("id", "lines_" + conversationname)
        input = conversationPage.find(".conversationinput")
        friendsButton = conversationPage.find(".conversationfriendsbutton")
        friendsButton.on "click", ->
          $.mobile.changePage "#friends"
            #,
            #transition: "none"
            #reverse: true


        input.attr "id", "input_" + conversationname
        input.on "keypress", {that: @}, (e) ->
          if e.which is 13
            text = $(@).val()
            chatcontroller.sendMessage conversationname, text
            if text and text.length > 0
              e.preventDefault()
              e.data.that.resetInput input

        $("#page_body").append conversationPage
        $.mobile.initializePage()

        #linesList.listview()
        #linesList.listview 'create'

        #apply data bindings
        conversationViewModel = new ConversationViewModel(remoteusername, conversationname)
        conversationViewModel.load =>


          for element in  $(conversationPage).find('.conversationcontent')
            ko.applyBindings conversationViewModel, element
          for element in $('.newMessagesCount, .messageCountTotal, .ss-logout')
            ko.applyBindings @, element


          @_scrollConversation conversationname
          $.mobile.changePage conversationPage

            #, transition: "slide"

    uiController = new UIController()
    $.each($('.newMessagesCount, .messageCountTotal, .ss-logout'), (index, value) ->
      ko.applyBindings uiController, value)
    uiController