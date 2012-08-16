define ["jquery", "./viewmodels/UserViewModel"], ($, UserViewModel) ->
  refreshListview: (element) ->
    element.listview "refresh"
    $(document).trigger "updatelayout"

  addListviewItem: (list, text, cssclass) ->
    list.append $("<li>").append($("<a/>")).addClass(if cssclass then cssclass else "\"friendclick\">").append(text)




  getRoomName: (remoteusername) ->
    username = UserViewModel.getUsername()
    if username < remoteusername then username + "_" + remoteusername else remoteusername + "_" + username


