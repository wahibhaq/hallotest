define [
  "jquery",
  "knockout",
  './ListViewModel',
  "./UserViewModel"
  'networkcontroller',
  'uicontroller',
  'chatcontroller'
  'utils'], ($, ko, ListViewModel, UserViewModel, networkcontroller, uicontroller, chatcontroller, utils) ->
    class FriendsViewModel extends ListViewModel
      title: ko.computed ->
        "surespot / #{UserViewModel.username()} / friends"

      constructor: ->
        super()
        chatcontroller.setFriendCallback @friendHandler

      getNewMessageCount: (room) -> uicontroller.getNewMessageCount room
      totalMessageCount: uicontroller.totalMessageCount

      load: () ->
        networkcontroller.getFriends (data) =>
          #$.each data, (index, value) =>
          @itemList?.removeAll()
          # chuck the room in there so we can bind it
          # todo decouple users and rooms "spots"
          ko.utils.arrayPushAll @itemList, data
          @itemList.valueHasMutated()


      friendClick: (data, event) ->
        uicontroller.createOrShowConversation data

      friendHandler: (fname) =>
        console.log "adding new friend #{fname}"
        @addItem fname



   #   addFriend: (fname) ->
        #tell the socket to join the room
      #  console.log "joining room"
      #  chatcontroller.emit "join", utils.getRoomName(fname)
#        @addItem fname

      #_createFriend: (fname) ->
       # { friendname: fname, room: utils.getRoomName(fname)}

      logout: ->
        uicontroller.logout()

      navClick: ->
        $.mobile.changePage "#friends"

    $("#blinkerinput").bind "keypress", (e) ->
      if e.which is 13
        text = $(this).val()
        if text and text.length > 0
          #see if the user is already in the list
          networkcontroller.invite text, (data, status, jqXHR) ->
            #  if jqXHR.status is 202
            #todo update pending/accepted status
            #utils.addListviewItem $("#friendslist"), text, "pending"
            #$("#friendslist").listview()
            #$("#friendslist").listview "refresh"
            #$.silentScroll(document.height);
            #, ->


            #todo inform user of error
          uicontroller.resetInput $(this)

    friendsViewModel = new FriendsViewModel()
    for element in  $('#friendscontent, .friends-vm')
      ko.applyBindings friendsViewModel, element
    friendsViewModel.load()
    friendsViewModel