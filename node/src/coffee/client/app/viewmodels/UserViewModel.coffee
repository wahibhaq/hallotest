define ["knockout"], (ko) ->
  class UserViewModel
    username: ko.observable()


    getUsername: ->
      username = @username() ? sessionStorage.getItem('username') ? null
      #? localStorage.getItem('lastsureshotuser')
      @username username
      username

    setUsername: (username) ->
      @username username
      sessionStorage.setItem 'username', username
      #localStorage.setItem 'lastsureshotuser', usernamecontroller.symDecrypt(message.room, message.text)

  userViewModel = new UserViewModel()
  userViewModel