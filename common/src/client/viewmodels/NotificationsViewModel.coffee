define [\
"jquery",
"knockout",
'./ListViewModel',
'networkcontroller',
'./FriendsViewModel',
'./UserViewModel'
'chatcontroller'], (
$,
ko,
ListViewModel,
networkcontroller,
FriendsViewModel,
UserViewModel,
chatcontroller) ->
  class NotificationsViewModel extends ListViewModel
    title: ko.computed ->
      "surespot / #{UserViewModel.username()} / notifications"

    constructor: ->
      console.log "NotificationsViewModel constructor"
      super()
      chatcontroller.setNotificationCallback @notificationHandler


    load: ->
      networkcontroller.getNotifications (data) =>
        @itemList?.removeAll()
        if (data?.length > 0)
          ko.utils.arrayPushAll @itemList, data
          @itemList.valueHasMutated()

    navClick: ->
      $.mobile.changePage "#notifications"


    notificationClick: (notification, event, data) ->
      if notification.type is 'invite'
        #tell server if we accepted or ignored
        networkcontroller.respondToInvite notification.data, data, =>
          #update our shit locally if we accepted the bastard as a friend
          if data is 'accept'
            FriendsViewModel.addFriend notification.data
          #remove notification
          @itemList.remove(notification)

    #todo error handling

    notificationHandler: (notification) =>
      #ask user if they want to add the user as a f
      console.log "received notification, type: #{notification.type}, data: #{notification.data}"
      @addItem notification


  #can decouple this if we want
  notificationsViewModel = new NotificationsViewModel()

  #$(document).bind "ready", (event) ->
  $.each($('#notificationscontent, .notifications-vm'), (index, value) ->
    ko.applyBindings notificationsViewModel, value)
  notificationsViewModel.load()

  return notificationsViewModel
