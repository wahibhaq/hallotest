#= require_tree .


requirejs.config
  shim:
    "socket.io":
      exports: "io"
  #todo build config
  paths:
    jquery: "../lib/jquery-1.7.2"
    jqm: "../lib/jquery.mobile-1.1.1"
    "socket.io": "../lib/socket.io"
    knockout: "../lib/knockout-2.1.0.debug"


# Start the main app logic
require [\
"jquery",
'knockout',
"./chatcontroller",
'./uicontroller',
"./usercontroller",
"./viewmodels/UserViewModel",
"./viewmodels/FriendsViewModel",
"./viewmodels/ListViewModel",
"./viewmodels/NotificationsViewModel"],  (
$,
ko
chatController,
uiController) ->






  redirectToConversation = (event, locationHash) ->
    index = locationHash.indexOf("#conversation")
    if index > -1
      event.preventDefault()
      console.log "redirectToConversation: " + locationHash
      uiController.recreateConversation(locationHash)


  ###
  if the user refreshed we want to show whatever page we were on before
  but in the case of the conversation pages we are generating them dynamically
  so we need to rebuild the page
  ###
  $(document).one "pagebeforechange", (event, data) ->
    if typeof data.toPage is "string"
      console.log "pagebeforechange: " + data.toPage
      redirectToConversation event, data.toPage
    else
      console.log "pagebeforechange: " + data.toPage[0].id
      if location.hash.indexOf("#conversation_") > -1
        redirectToConversation event, location.hash




  ###ko.bindingHandlers.jqmPage =
    init: (element, valueAccessor) ->
      # if element? and element.length > 0
      console.log 'jqmPage init,  element: ' + element
      #ko.utils.unwrapObservable valueAccessor() #just to create a dependency
      setTimeout (-> #To make sure the refresh fires after the DOM is updated
        $(element).parent('div')[0].updateLayout()
      ), 0,

    update: (element, valueAccessor) ->
        # if element? and element.length > 0
      console.log 'jqmPage, element: ' + element
      #ko.utils.unwrapObservable valueAccessor() #just to create a dependency
      setTimeout (-> #To make sure the refresh fires after the DOM is updated
        $(element).parent('div')[0].updateLayout()
      ), 0###

  chatController.connect()

    #if it's a conversation page we rebuild it and show it at which point we make the body visible
  #if not location.hash.indexOf("#conversation_") > -1

  $(document).bind "ready", ->
    console.log 'ready'
    $("body").css "visibility", "visible"





  $(document).bind "mobileinit", ->
    console.log "mobileinit"
    $.mobile.defaultPageTransition = 'none'
    $.mobile.allowCrossDomainPages = true
    $.support.cors = true
    $.ajaxSetup
      contentType: "application/json; charset=utf-8"
      statusCode:
        401: ->

          # Redirect the to the login page.
          $.mobile.changePage "#login"
            #,
            #transition: "slide"

  require ['jqm'], ->

    ko.bindingHandlers.jqmRefreshList =
      update: (element, valueAccessor) ->
        # if element? and element.length > 0

        console.log 'jqmRefreshList, element css: ' + $(element).attr('class')
        #  if element.listview?
        #ko.utils.unwrapObservable valueAccessor() #just to create a dependency
        setTimeout (-> #To make sure the refresh fires after the DOM is updated
          $(element).trigger('create')
          $(element).listview()
          $(element).listview "refresh"
        ), 100